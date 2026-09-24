package com.github.xingjianluo.springbootiamjava.tests;

import com.github.xingjianluo.springbootiamjava.audit.AuditEvent;
import com.github.xingjianluo.springbootiamjava.audit.AuditService;
import com.github.xingjianluo.springbootiamjava.authz.AuthorizationDecision;
import com.github.xingjianluo.springbootiamjava.authz.AuthorizationRequest;
import com.github.xingjianluo.springbootiamjava.authz.Effect;
import com.github.xingjianluo.springbootiamjava.authz.PolicyEngine;
import com.github.xingjianluo.springbootiamjava.authz.PolicyRepository;
import com.github.xingjianluo.springbootiamjava.authz.PolicyRule;
import com.github.xingjianluo.springbootiamjava.subject.SubjectDirectory;
import com.github.xingjianluo.springbootiamjava.subject.SubjectProfile;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 授权判定优先级与收敛：
 * 1) 显式 DENY 优先于任何 ALLOW（即使 ALLOW 优先级更高、角色命中）；
 * 2) 策略变更后新版本立即一致收敛，不存在短暂越权；
 * 3) 主体角色变更（快照版本）后结果一致收敛，不沿用旧权限；
 * 4) 无规则匹配默认拒绝；输入/依赖异常 -> INDETERMINATE 且拒绝。
 */
@SpringBootTest
class ExplicitDenyPriorityTest {

    @Autowired
    private PolicyEngine policyEngine;
    @Autowired
    private PolicyRepository policyRepository;
    @Autowired
    private SubjectDirectory subjectDirectory;
    @Autowired
    private AuditService auditService;

    @BeforeEach
    void reset() {
        policyRepository.clear();
        subjectDirectory.clear();
        auditService.clear();
    }

    @Test
    void explicitDenyOverridesAllowEvenWhenAllowHasHigherPriority() {
        subjectDirectory.upsert("carol", Set.of("admin", "auditor"), Map.of("dept", "finance"));
        policyRepository.replaceAll(List.of(
                new PolicyRule("allow-admin-all", Effect.ALLOW, null, "finance", "*",
                        Set.of("admin"), null, null, 1000),
                new PolicyRule("deny-auditor-finance", Effect.DENY, null, "finance", "*",
                        Set.of("auditor"), null, null, 1)));

        AuthorizationDecision d = decide("carol", "finance", "read");
        TestReport.log("deny-priority",
                "input=carol/finance/read roles={admin,auditor} => allow=" + d.allow()
                        + " matched=" + d.matchedRule() + " basis=" + d.basis());
        assertFalse(d.allow());
        assertEquals(AuthorizationDecision.REASON_DENY_RULE, d.reason());
        assertEquals("deny-auditor-finance", d.matchedRule());
    }

    @Test
    void attributeDenyOverridesRoleAllow() {
        subjectDirectory.upsert("dave", Set.of("member"), Map.of("clearance", "low"));
        policyRepository.replaceAll(List.of(
                new PolicyRule("allow-members", Effect.ALLOW, null, "secret", "read",
                        Set.of("member"), null, null, 10),
                new PolicyRule("deny-low-clearance", Effect.DENY, null, "secret", "read",
                        null, Map.of("clearance", "low"), null, 100)));

        AuthorizationDecision low = decide("dave", "secret", "read");
        TestReport.log("abac-deny", "clearance=low => allow=" + low.allow() + " basis=" + low.basis());
        assertFalse(low.allow());

        // 属性提升后：新快照一致允许
        subjectDirectory.upsert("dave", Set.of("member"), Map.of("clearance", "high"));
        AuthorizationDecision high = decide("dave", "secret", "read");
        TestReport.log("abac-allow-after-change",
                "clearance=high subjectVersion=" + high.subjectVersion()
                        + " => allow=" + high.allow() + " basis=" + high.basis());
        assertTrue(high.allow());
        assertEquals(low.subjectVersion() + 1, high.subjectVersion(),
                "角色/属性变更必须产生新版本快照，判定随版本收敛");
    }

    @Test
    void policyChangeConvergesImmediatelyWithoutTransientOverGrant() {
        subjectDirectory.upsert("erin", Set.of("reader"), Map.of());
        policyRepository.replaceAll(List.of(
                new PolicyRule("allow-reader", Effect.ALLOW, null, "docs", "read",
                        Set.of("reader"), null, null, 1)));

        assertTrue(decide("erin", "docs", "read").allow());

        // 策略整体替换为拒绝（空策略集）：此后每次判定都必须拒绝，不能沿用旧版本
        long oldVersion = policyRepository.snapshot().version();
        policyRepository.replaceAll(List.of());
        long newVersion = policyRepository.snapshot().version();
        assertTrue(newVersion > oldVersion);
        for (int i = 0; i < 50; i++) {
            AuthorizationDecision d = decide("erin", "docs", "read");
            assertFalse(d.allow(), "no transient allow after policy replacement");
            assertEquals(AuthorizationDecision.REASON_DEFAULT_DENY, d.reason());
            assertEquals(newVersion, d.policyVersion());
        }
        TestReport.log("policy-converge",
                "policyVersion " + oldVersion + "->" + newVersion + ", 50/50 DEFAULT_DENY");
    }

    @Test
    void roleRemovalConvergesAndNeverUsesStalePermissions() {
        subjectDirectory.upsert("frank", Set.of("reader"), Map.of());
        policyRepository.replaceAll(List.of(
                new PolicyRule("allow-reader", Effect.ALLOW, null, "docs", "read",
                        Set.of("reader"), null, null, 1)));
        assertTrue(decide("frank", "docs", "read").allow());

        // 移除角色
        SubjectProfile updated = subjectDirectory.upsert("frank", Set.of(), Map.of());
        AuthorizationDecision d = decide("frank", "docs", "read");
        TestReport.log("role-removal",
                "rolesNow=[] subjectVersion=" + updated.version() + " => allow=" + d.allow()
                        + " reason=" + d.reason());
        assertFalse(d.allow());
        assertEquals(AuthorizationDecision.REASON_DEFAULT_DENY, d.reason());
        assertEquals(updated.version(), d.subjectVersion());
    }

    @Test
    void missingSubjectAndIndeterminateInputsFailClosed() {
        // 未登记主体：空画像 -> 默认拒绝（不抛异常给调用方，但绝不放行）
        AuthorizationDecision ghost = decide("ghost", "docs", "read");
        assertFalse(ghost.allow());
        assertEquals(AuthorizationDecision.REASON_DEFAULT_DENY, ghost.reason());

        // 不完整输入 -> INDETERMINATE 拒绝，且可与策略拒绝区分
        AuthorizationDecision bad = policyEngine.evaluate(
                new AuthorizationRequest(null, "docs", "read", Map.of(), Map.of()));
        TestReport.log("indeterminate", "null-subject => allow=" + bad.allow()
                + " reason=" + bad.reason());
        assertFalse(bad.allow());
        assertEquals(AuthorizationDecision.REASON_INDETERMINATE, bad.reason());

        // 审计里策略拒绝同样可区分（由 AccessGuard 链路测试覆盖写入，这里校验纯引擎结论可解释）
        TestReport.log("default-vs-indeterminate",
                "defaultDeny=" + AuthorizationDecision.REASON_DEFAULT_DENY
                        + " indeterminate=" + bad.reason());
    }

    private AuthorizationDecision decide(String subject, String resource, String action) {
        SubjectProfile profile = subjectDirectory.snapshot(subject);
        return policyEngine.evaluate(new AuthorizationRequest(
                profile, resource, action, Map.of(), Map.of()));
    }
}
