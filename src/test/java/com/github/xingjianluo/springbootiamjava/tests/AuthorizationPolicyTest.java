package com.github.xingjianluo.springbootiamjava.tests;

import static org.assertj.core.api.Assertions.assertThat;

import com.github.xingjianluo.springbootiamjava.iam.authz.DefaultPolicyEvaluator;
import com.github.xingjianluo.springbootiamjava.iam.authz.InMemoryAuthzStore;
import com.github.xingjianluo.springbootiamjava.iam.error.ErrorCode;
import com.github.xingjianluo.springbootiamjava.iam.error.IamException;
import com.github.xingjianluo.springbootiamjava.iam.model.AuthzDecision;
import com.github.xingjianluo.springbootiamjava.iam.model.AuthzRequest;
import com.github.xingjianluo.springbootiamjava.iam.model.DecisionReason;
import com.github.xingjianluo.springbootiamjava.iam.model.Policy;
import com.github.xingjianluo.springbootiamjava.iam.model.PolicyEffect;
import com.github.xingjianluo.springbootiamjava.iam.model.SubjectAttributes;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 授权判定测试：显式 DENY 优先、默认拒绝、RBAC/ABAC 命中、
 * 策略/属性变更按修订边界一致收敛、依赖异常失败关闭。
 */
class AuthorizationPolicyTest {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationPolicyTest.class);

    private final InMemoryAuthzStore store = new InMemoryAuthzStore();
    private final DefaultPolicyEvaluator evaluator = new DefaultPolicyEvaluator(store);

    private AuthzRequest req(String subject, List<String> roles, String resource, String action) {
        return new AuthzRequest(subject, roles, null, resource, action);
    }

    @Test
    void explicitDeny_takesPrecedenceOverAllow() {
        store.upsertPolicy(new Policy("allow-all", PolicyEffect.ALLOW,
                "docs/", "read", List.of("reader"), Map.of()));
        store.upsertPolicy(new Policy("deny-secret", PolicyEffect.DENY,
                "docs/secret", "read", List.of("reader"), Map.of()));

        AuthzDecision d = evaluator.evaluate(req("alice", List.of("reader"), "docs/secret", "read"));
        log.info("input: subject=alice, roles=[reader], resource=docs/secret, action=read");
        log.info("basis: allow={}, reason={}, matched={}", d.allow(), d.reason(), d.matchedPolicyIds());
        assertThat(d.allow()).isFalse();
        assertThat(d.reason()).isEqualTo(DecisionReason.EXPLICIT_DENY);
        assertThat(d.matchedPolicyIds()).containsExactly("deny-secret");

        // 非 secret 资源只有 ALLOW 命中 -> 放行
        AuthzDecision other = evaluator.evaluate(req("alice", List.of("reader"), "docs/public", "read"));
        assertThat(other.allow()).isTrue();
        assertThat(other.reason()).isEqualTo(DecisionReason.ALLOW);
    }

    @Test
    void noMatchingPolicy_defaultsToDeny() {
        store.upsertPolicy(new Policy("allow-read", PolicyEffect.ALLOW,
                "docs/", "read", List.of("reader"), Map.of()));
        AuthzDecision wrongAction = evaluator.evaluate(req("alice", List.of("reader"), "docs/a", "write"));
        AuthzDecision noRole = evaluator.evaluate(req("alice", List.of(), "docs/a", "read"));
        log.info("basis: wrongAction.reason={}, noRole.reason={} (both must be NO_MATCHING_POLICY)",
                wrongAction.reason(), noRole.reason());
        assertThat(wrongAction.allow()).isFalse();
        assertThat(wrongAction.reason()).isEqualTo(DecisionReason.NO_MATCHING_POLICY);
        assertThat(noRole.reason()).isEqualTo(DecisionReason.NO_MATCHING_POLICY);
    }

    @Test
    void attributeBasedPolicy_usesSnapshotAttributes() {
        // 仅当 department=security 时允许
        store.upsertPolicy(new Policy("abac-security", PolicyEffect.ALLOW,
                "vault/", "open", List.of(), Map.of("department", "security")));
        store.upsertSubject(new SubjectAttributes("bob", Map.of("department", "engineering"), 1L));

        AuthzDecision denied = evaluator.evaluate(req("bob", List.of(), "vault/box", "open"));
        assertThat(denied.allow()).isFalse();
        log.info("input: bob department=engineering -> basis: {}", denied.reason());

        // 属性变更：随新快照生效，立即一致收敛，不沿用旧属性。
        store.upsertSubject(new SubjectAttributes("bob", Map.of("department", "security"), 2L));
        AuthzDecision allowed = evaluator.evaluate(req("bob", List.of(), "vault/box", "open"));
        log.info("input: bob department=security  -> basis: allow={}, matched={}, revision={}",
                allowed.allow(), allowed.matchedPolicyIds(), allowed.policyRevision());
        assertThat(allowed.allow()).isTrue();
        assertThat(allowed.matchedPolicyIds()).containsExactly("abac-security");
        assertThat(allowed.policyRevision()).isGreaterThan(denied.policyRevision());
    }

    @Test
    void policyChange_convergesAtRevisionBoundary() {
        store.upsertSubject(new SubjectAttributes("carol", Map.of(), 0L));
        // 初始无策略：默认拒绝
        AuthzDecision before = evaluator.evaluate(req("carol", List.of("reader"), "docs/x", "read"));
        assertThat(before.reason()).isEqualTo(DecisionReason.NO_MATCHING_POLICY);

        store.upsertPolicy(new Policy("allow", PolicyEffect.ALLOW,
                "docs/", "read", List.of("reader"), Map.of()));
        AuthzDecision afterAllow = evaluator.evaluate(req("carol", List.of("reader"), "docs/x", "read"));
        assertThat(afterAllow.allow()).isTrue();

        // 变更为 DENY：不得短暂越权，之后一致拒绝
        store.upsertPolicy(new Policy("allow", PolicyEffect.DENY,
                "docs/", "read", List.of("reader"), Map.of()));
        AuthzDecision afterDeny = evaluator.evaluate(req("carol", List.of("reader"), "docs/x", "read"));
        log.info("basis: revisions defaultDeny={} -> allow={} -> deny={}",
                before.policyRevision(), afterAllow.policyRevision(), afterDeny.policyRevision());
        assertThat(afterDeny.allow()).isFalse();
        assertThat(afterDeny.reason()).isEqualTo(DecisionReason.EXPLICIT_DENY);

        // 删除策略后回到默认拒绝
        assertThat(store.removePolicy("allow")).isTrue();
        AuthzDecision removed = evaluator.evaluate(req("carol", List.of("reader"), "docs/x", "read"));
        assertThat(removed.reason()).isEqualTo(DecisionReason.NO_MATCHING_POLICY);
    }

    @Test
    void dependencyFailure_failsClosed_asIndeterminate() {
        store.setFaulty(true);
        ErrorCode code = null;
        try {
            evaluator.evaluate(req("dan", List.of(), "docs/x", "read"));
        } catch (IamException e) {
            code = e.errorCode();
        }
        log.info("input: authz store faulty -> basis: errorCode={}", code);
        assertThat(code).isEqualTo(ErrorCode.AUTHZ_INDETERMINATE);
    }
}
