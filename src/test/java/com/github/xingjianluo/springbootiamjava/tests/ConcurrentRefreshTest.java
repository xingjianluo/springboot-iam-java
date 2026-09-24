package com.github.xingjianluo.springbootiamjava.tests;

import com.github.xingjianluo.springbootiamjava.audit.AuditService;
import com.github.xingjianluo.springbootiamjava.common.ApiException;
import com.github.xingjianluo.springbootiamjava.common.ErrorCode;
import com.github.xingjianluo.springbootiamjava.credential.CredentialService;
import com.github.xingjianluo.springbootiamjava.credential.CredentialStore;
import com.github.xingjianluo.springbootiamjava.credential.CredentialView;
import com.github.xingjianluo.springbootiamjava.credential.InMemoryCredentialStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 并发刷新：同一凭证的并发刷新必须恰好一次成功（轮换），
 * 其余全部以可区分的 REFRESH_CONFLICT 失败；旧凭证立即失效。
 */
@SpringBootTest
class ConcurrentRefreshTest {

    private static final int THREADS = 16;

    @Autowired
    private CredentialService credentialService;

    @Autowired
    private CredentialStore credentialStore;

    @Autowired
    private AuditService auditService;

    @BeforeEach
    void reset() {
        ((InMemoryCredentialStore) credentialStore).clear();
        auditService.clear();
    }

    @AfterEach
    void restore() {
        auditService.setWritable(true);
    }

    @Test
    void concurrentRefreshOnlyOneSucceedsAndOldCredentialDiesImmediately() throws Exception {
        CredentialView issued = credentialService.issue("alice", 60_000L);
        String oldToken = issued.token();
        TestReport.log("refresh-input", "subject=alice threads=" + THREADS
                + " oldToken=" + oldToken + " version=" + issued.version());

        CyclicBarrier barrier = new CyclicBarrier(THREADS);
        ExecutorService pool = Executors.newFixedThreadPool(THREADS);
        List<String> outcomes = new CopyOnWriteArrayList<>();
        List<String> newTokens = new CopyOnWriteArrayList<>();
        try {
            List<Future<?>> futures = new java.util.ArrayList<>();
            for (int i = 0; i < THREADS; i++) {
                futures.add(pool.submit(() -> {
                    try {
                        barrier.await(5, TimeUnit.SECONDS);
                        CredentialView view = credentialService.refresh(oldToken);
                        outcomes.add("SUCCESS:" + view.version());
                        newTokens.add(view.token());
                    } catch (ApiException ex) {
                        outcomes.add("FAIL:" + ex.errorCode().code());
                    } catch (Exception ex) {
                        outcomes.add("FAIL:OTHER:" + ex.getClass().getSimpleName());
                    }
                }));
            }
            for (Future<?> f : futures) {
                f.get(10, TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
        }

        long success = outcomes.stream().filter(o -> o.startsWith("SUCCESS")).count();
        long conflicts = outcomes.stream()
                .filter(o -> o.equals("FAIL:" + ErrorCode.REFRESH_CONFLICT.code())).count();
        TestReport.log("refresh-outcome", "results=" + outcomes);

        assertEquals(1, success, "exactly one concurrent refresh must succeed");
        assertEquals(THREADS - 1, conflicts, "all losers must fail with REFRESH_CONFLICT");
        assertEquals(1, newTokens.size(), "only one new credential may exist");

        // 旧凭证立即失效：再刷新旧凭证必须得到 REFRESH_CONFLICT（可区分于 INVALID/EXPIRED/REVOKED）
        ApiException stale = expectApi(() -> credentialService.refresh(oldToken));
        TestReport.log("refresh-old-after-rotation",
                "oldToken=" + oldToken + " => " + stale.errorCode().code());
        assertEquals(ErrorCode.REFRESH_CONFLICT, stale.errorCode());

        // 新凭证可继续刷新，形成版本 3，且链上只有一个 ACTIVE 版本
        CredentialView v3 = credentialService.refresh(newTokens.get(0));
        assertNotNull(v3);
        assertEquals(3, v3.version());
        ApiException v1Again = expectApi(() -> credentialService.refresh(oldToken));
        assertEquals(ErrorCode.REFRESH_CONFLICT, v1Again.errorCode());
        ApiException v2Again = expectApi(() -> credentialService.refresh(newTokens.get(0)));
        assertEquals(ErrorCode.REFRESH_CONFLICT, v2Again.errorCode());
        TestReport.log("refresh-chain-final", "activeVersion=3, v1/v2 rejected as REFRESH_CONFLICT");

        // 审计必须能还原每次成功轮换
        long rotations = auditService.findBySubject("alice").stream()
                .filter(e -> "CREDENTIAL_REFRESH".equals(e.action()) && "ROTATED".equals(e.result()))
                .count();
        assertTrue(rotations >= 2, "each successful rotation must be audited");
        TestReport.log("refresh-audit", "rotatedAuditCount=" + rotations);
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
