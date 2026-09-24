package com.github.xingjianluo.springbootiamjava.tests;

import com.github.xingjianluo.springbootiamjava.audit.AuditService;
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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * 撤销与在途请求交错：利用公平链锁精确控制排队顺序。
 * 结论必须确定：已撤销凭证此后对任何入口都不可用，不存在"撤销后仍放行"。
 */
@SpringBootTest
class RevocationRaceTest {

    private static final int REPEATS = 20;

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
        subjectDirectory.upsert("bob", java.util.Set.of("reader"), Map.of());
        policyRepository.replaceAll(java.util.List.of(
                new PolicyRule("allow-reader-docs-read", Effect.ALLOW, null, "docs", "read",
                        java.util.Set.of("reader"), null, null, 100)));
    }

    @RepeatedTest(REPEATS)
    void revokeQueuedFirstCommitsFirstAndAllLaterAccessIsRejected() throws Exception {
        CredentialView issued = credentialService.issue("bob", 60_000L);
        String token = issued.token();

        ExecutorService pool = Executors.newFixedThreadPool(3);
        CountDownLatch holderInside = new CountDownLatch(1);
        CountDownLatch releaseHolder = new CountDownLatch(1);
        AtomicReference<String> revokeResult = new AtomicReference<>("none");
        AtomicReference<String> accessResult = new AtomicReference<>("none");

        try {
            // 持锁线程先拿到链锁，revoker/access 依次排队；最后由持锁线程自己释放
            Future<?> holder = pool.submit(() -> {
                credentialStore.lockChainOf(token);
                holderInside.countDown();
                try {
                    releaseHolder.await(5, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                credentialStore.findChain(issued.chainId()).lock().unlock();
            });
            holderInside.await(2, TimeUnit.SECONDS);

            Future<?> revoker = pool.submit(() -> {
                try {
                    credentialService.revoke(token, "security-incident");
                    revokeResult.set("REVOKED");
                } catch (ApiException ex) {
                    revokeResult.set(ex.errorCode().code());
                }
            });
            // 给 revoker 足够时间先进入公平等待队列
            Thread.sleep(30);

            Future<?> accessor = pool.submit(() -> {
                try {
                    accessGuard.authorizeAccess(token, "docs", "read", Map.of(), Map.of());
                    accessResult.set("ALLOWED");
                } catch (ApiException ex) {
                    accessResult.set(ex.errorCode().code());
                }
            });
            Thread.sleep(30); // access 排在 revoker 之后

            releaseHolder.countDown(); // 公平锁：revoker 先获锁先提交
            holder.get(5, TimeUnit.SECONDS);
            revoker.get(5, TimeUnit.SECONDS);
            accessor.get(5, TimeUnit.SECONDS);
        } finally {
            pool.shutdownNow();
        }

        TestReport.log("revoke-first-interleave",
                "revoke=" + revokeResult.get() + " access=" + accessResult.get()
                        + " input=token " + token.substring(0, 16) + "...");
        assertEquals("REVOKED", revokeResult.get());
        assertEquals(ErrorCode.CREDENTIAL_REVOKED.code(), accessResult.get());

        // 撤销提交后：旧凭证对访问与刷新都永久不可用
        ApiException later = expectApi(() ->
                accessGuard.authorizeAccess(token, "docs", "read", Map.of(), Map.of()));
        assertEquals(ErrorCode.CREDENTIAL_REVOKED, later.errorCode());
    }

    @RepeatedTest(REPEATS)
    void accessInsideCriticalSectionMayPassButAllPostRevocationAccessFails() throws Exception {
        CredentialView issued = credentialService.issue("bob", 60_000L);
        String token = issued.token();

        // 撤销前的在途访问：正常放行
        AccessGuard.GuardResult granted =
                accessGuard.authorizeAccess(token, "docs", "read", Map.of(), Map.of());
        assertNotNull(granted);

        CredentialView revoked = credentialService.revoke(token, "manual");
        assertEquals("manual", revoked.revokeReason());

        int rounds = 32;
        ExecutorService pool = Executors.newFixedThreadPool(8);
        try {
            java.util.List<Future<String>> futures = new java.util.ArrayList<>();
            for (int i = 0; i < rounds; i++) {
                futures.add(pool.submit(() -> {
                    try {
                        accessGuard.authorizeAccess(token, "docs", "read", Map.of(), Map.of());
                        return "ALLOWED";
                    } catch (ApiException ex) {
                        return ex.errorCode().code();
                    }
                }));
            }
            for (Future<String> f : futures) {
                String r = f.get(5, TimeUnit.SECONDS);
                assertEquals(ErrorCode.CREDENTIAL_REVOKED.code(), r,
                        "no access may succeed after revocation commits");
            }
        } finally {
            pool.shutdownNow();
        }
        TestReport.log("post-revoke-flood", "rounds=" + rounds + " all=CREDENTIAL_REVOKED");

        // 撤销覆盖整条链：轮换后撤销新凭证，旧凭证同样不可用
        CredentialView v2 = credentialService.issue("bob", 60_000L);
        String t1 = v2.token();
        CredentialView v2b = credentialService.refresh(t1);
        credentialService.revoke(v2b.token(), "chain-kill");
        ApiException oldDead = expectApi(() ->
                accessGuard.authorizeAccess(t1, "docs", "read", Map.of(), Map.of()));
        ApiException newDead = expectApi(() ->
                accessGuard.authorizeAccess(v2b.token(), "docs", "read", Map.of(), Map.of()));
        TestReport.log("chain-revoke",
                "rotatedOld=" + oldDead.errorCode().code() + " current=" + newDead.errorCode().code());
        assertEquals(ErrorCode.CREDENTIAL_REVOKED, oldDead.errorCode());
        assertEquals(ErrorCode.CREDENTIAL_REVOKED, newDead.errorCode());
    }

    static ApiException expectApi(ThrowingRunnable runnable) {
        try {
            runnable.run();
            throw new AssertionError("expected ApiException");
        } catch (ApiException expected) {
            return expected;
        }
    }

    @FunctionalInterface
    interface ThrowingRunnable {
        void run();
    }
}
