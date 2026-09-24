package com.github.xingjianluo.springbootiamjava.tests;

import com.github.xingjianluo.springbootiamjava.audit.AuditService;
import com.github.xingjianluo.springbootiamjava.common.ApiException;
import com.github.xingjianluo.springbootiamjava.common.ErrorCode;
import com.github.xingjianluo.springbootiamjava.credential.CredentialService;
import com.github.xingjianluo.springbootiamjava.credential.CredentialStore;
import com.github.xingjianluo.springbootiamjava.credential.CredentialView;
import com.github.xingjianluo.springbootiamjava.credential.InMemoryCredentialStore;
import com.github.xingjianluo.springbootiamjava.guard.AccessGuard;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** 过期凭证：访问与刷新都得到可区分的 CREDENTIAL_EXPIRED。 */
@SpringBootTest
class CredentialExpiryTest {

    @Autowired
    private CredentialService credentialService;
    @Autowired
    private AccessGuard accessGuard;
    @Autowired
    private CredentialStore credentialStore;
    @Autowired
    private AuditService auditService;

    @BeforeEach
    void reset() {
        ((InMemoryCredentialStore) credentialStore).clear();
        auditService.clear();
    }

    @Test
    void expiredCredentialIsRejectedWithDistinctCodeAtEveryEntry() throws Exception {
        CredentialView v = credentialService.issue("ivan", 1L);
        TestReport.log("expiry-input", "subject=ivan ttlMillis=1 token=" + v.token());
        Thread.sleep(5);

        ApiException accessError = expectApi(() ->
                accessGuard.authorizeAccess(v.token(), "docs", "read", Map.of(), Map.of()));
        ApiException refreshError = expectApi(() -> credentialService.refresh(v.token()));

        TestReport.log("expiry-outcome",
                "access=" + accessError.errorCode().code() + " refresh=" + refreshError.errorCode().code());
        assertEquals(ErrorCode.CREDENTIAL_EXPIRED, accessError.errorCode());
        assertEquals(ErrorCode.CREDENTIAL_EXPIRED, refreshError.errorCode());

        long expiredAudit = auditService.findBySubject("ivan").stream()
                .filter(e -> "RESOURCE_ACCESS".equals(e.action())
                        && ErrorCode.CREDENTIAL_EXPIRED.code().equals(e.reason()))
                .count();
        assertEquals(1, expiredAudit, "expired access must be audited");
    }

    static ApiException expectApi(Runnable runnable) {
        try {
            runnable.run();
            throw new AssertionError("expected ApiException");
        } catch (ApiException expected) {
            return expected;
        }
    }
}
