package com.github.xingjianluo.springbootiamjava.tests;

import com.github.xingjianluo.springbootiamjava.audit.AuditEvent;
import com.github.xingjianluo.springbootiamjava.audit.AuditService;
import com.github.xingjianluo.springbootiamjava.audit.AuditUnavailableException;
import com.github.xingjianluo.springbootiamjava.common.ApiException;
import com.github.xingjianluo.springbootiamjava.common.ErrorCode;
import com.github.xingjianluo.springbootiamjava.credential.CredentialService;
import com.github.xingjianluo.springbootiamjava.credential.CredentialStore;
import com.github.xingjianluo.springbootiamjava.credential.CredentialView;
import com.github.xingjianluo.springbootiamjava.credential.InMemoryCredentialStore;
import com.github.xingjianluo.springbootiamjava.guard.AccessGuard;
import com.github.xingjianluo.springbootiamjava.authz.Effect;
import com.github.xingjianluo.springbootiamjava.authz.PolicyRepository;
import com.github.xingjianluo.springbootiamjava.authz.PolicyRule;
import com.github.xingjianluo.springbootiamjava.subject.SubjectDirectory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 审计失败语义：审计不可写时，所有受保护操作不得放行/提交（fail-closed），
 * 失败原因为 AUDIT_UNAVAILABLE，与凭证类、策略类错误可区分；恢复后链路自动正常。
 */
@SpringBootTest
class AuditFailureTest {

    @Autowired
    private CredentialService credentialService;
    @Autowired
    private AccessGuard accessGuard;
    @Autowired
    private CredentialStore credentialStore;
    @Autowired
    private SubjectDirectory subjectDirectory;
    @Autowired
    private PolicyRepository policyRepository;
    @Autowired
    private AuditService auditService;

    @BeforeEach
    void reset() {
        ((InMemoryCredentialStore) credentialStore).clear();
        auditService.clear();
        subjectDirectory.upsert("grace", Set.of("reader"), Map.of());
        policyRepository.replaceAll(List.of(
                new PolicyRule("allow-reader-docs", Effect.ALLOW, null, "docs", "read",
                        Set.of("reader"), null, null, 1)));
    }

    @AfterEach
    void restore() {
        auditService.setWritable(true);
    }

    @Test
    void accessIsNotAllowedWhenAuditIsUnwritable() {
        CredentialView issued = credentialService.issue("grace", 60_000L);
        // 故障前访问正常且有审计
        AccessGuard.GuardResult ok = accessGuard.authorizeAccess(
                issued.token(), "docs", "read", Map.of(), Map.of());
        assertEquals("grace", ok.subject());

        auditService.setWritable(false);
        TestReport.log("audit-down-input",
                "token=" + issued.token().substring(0, 16) + "... resource=docs action=read policy=ALLOW");

        AuditUnavailableException ex = assertThrows(AuditUnavailableException.class, () ->
                accessGuard.authorizeAccess(issued.token(), "docs", "read", Map.of(), Map.of()));
        TestReport.log("audit-down-outcome",
                "blockedWith=" + ex.getClass().getSimpleName()
                        + " (mapped to " + ErrorCode.AUDIT_UNAVAILABLE.code() + ")");

        // 关键断言：故障期间不存在任何 ALLOWED 记录，且受影响操作未被放行
        long allowedDuringOutage = auditService.findBySubject("grace").stream()
                .filter(e -> "RESOURCE_ACCESS".equals(e.action()) && "ALLOWED".equals(e.result()))
                .count();
        assertEquals(1, allowedDuringOutage,
                "no additional access may be allowed while audit is down");
    }

    @Test
    void credentialIssueAndRefreshAreBlockedWhenAuditIsUnwritable() {
        auditService.setWritable(false);

        // 签发不得产生任何可用凭证
        assertThrows(AuditUnavailableException.class,
                () -> credentialService.issue("grace", 60_000L));

        auditService.setWritable(true);
        CredentialView v1 = credentialService.issue("grace", 60_000L);
        auditService.setWritable(false);

        // 刷新失败：异常为审计类，且旧凭证仍然可用（轮换未提交）
        assertThrows(AuditUnavailableException.class,
                () -> credentialService.refresh(v1.token()));

        auditService.setWritable(true);
        AccessGuard.GuardResult stillUsable = accessGuard.authorizeAccess(
                v1.token(), "docs", "read", Map.of(), Map.of());
        TestReport.log("audit-down-refresh",
                "refresh blocked, old credential still usable, basis=" + stillUsable.decisionBasis());
        assertEquals("grace", stillUsable.subject());

        // 并发区分性：审计失败的刷新不会让随后正常刷新误判为 REFRESH_CONFLICT
        CredentialView v2 = credentialService.refresh(v1.token());
        assertEquals(2, v2.version());
        TestReport.log("audit-recovered-refresh", "old->version " + v2.version() + " success");
    }

    @Test
    void failureReasonsAreDistinguishableAcrossAllEntryPoints() {
        CredentialView v1 = credentialService.issue("grace", 60_000L);

        assertEquals(ErrorCode.CREDENTIAL_INVALID,
                expectCode(() -> accessGuard.authorizeAccess(
                        "cred-does-not-exist", "docs", "read", Map.of(), Map.of())));
        assertEquals(ErrorCode.CREDENTIAL_MISSING,
                expectCode(() -> accessGuard.authorizeAccess(
                        " ", "docs", "read", Map.of(), Map.of())));
        assertEquals(ErrorCode.AUTHZ_DENIED,
                expectCode(() -> accessGuard.authorizeAccess(
                        v1.token(), "docs", "write", Map.of(), Map.of())));

        auditService.setWritable(false);
        assertEquals(ErrorCode.AUDIT_UNAVAILABLE,
                expectCode(() -> credentialService.issue("grace", 60_000L)));
        auditService.setWritable(true);

        // 撤销后访问 => CREDENTIAL_REVOKED
        credentialService.revoke(v1.token(), "test");
        assertEquals(ErrorCode.CREDENTIAL_REVOKED,
                expectCode(() -> accessGuard.authorizeAccess(
                        v1.token(), "docs", "read", Map.of(), Map.of())));

        List<String> reasons = auditService.findBySubject("grace").stream()
                .map(AuditEvent::reason)
                .filter(r -> r != null)
                .toList();
        TestReport.log("distinguishable-reasons", "auditReasons=" + reasons);
        assertTrue(reasons.contains("test"));
    }

    private ErrorCode expectCode(Runnable runnable) {
        try {
            runnable.run();
            throw new AssertionError("expected failure");
        } catch (ApiException api) {
            return api.errorCode();
        } catch (AuditUnavailableException audit) {
            return ErrorCode.AUDIT_UNAVAILABLE;
        }
    }
}
