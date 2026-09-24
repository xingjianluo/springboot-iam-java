package com.github.xingjianluo.springbootiamjava.tests;

import static org.assertj.core.api.Assertions.assertThat;

import com.github.xingjianluo.springbootiamjava.iam.access.AccessServiceImpl;
import com.github.xingjianluo.springbootiamjava.iam.audit.AuditEvent;
import com.github.xingjianluo.springbootiamjava.iam.audit.AuditOutcome;
import com.github.xingjianluo.springbootiamjava.iam.audit.InMemoryAuditService;
import com.github.xingjianluo.springbootiamjava.iam.authz.DefaultPolicyEvaluator;
import com.github.xingjianluo.springbootiamjava.iam.authz.InMemoryAuthzStore;
import com.github.xingjianluo.springbootiamjava.iam.credential.CredentialService;
import com.github.xingjianluo.springbootiamjava.iam.credential.CredentialServiceImpl;
import com.github.xingjianluo.springbootiamjava.iam.credential.InMemoryCredentialStore;
import com.github.xingjianluo.springbootiamjava.iam.error.ErrorCode;
import com.github.xingjianluo.springbootiamjava.iam.error.IamException;
import com.github.xingjianluo.springbootiamjava.iam.model.Credential;
import com.github.xingjianluo.springbootiamjava.iam.model.Policy;
import com.github.xingjianluo.springbootiamjava.iam.model.PolicyEffect;
import com.github.xingjianluo.springbootiamjava.tests.support.ManualClock;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 撤销竞态测试：撤销与在途访问 / 在途刷新交错时结果必须确定，
 * 已撤销凭证绝不可能被放行；INVALID / EXPIRED / REVOKED 三类失败可区分。
 */
class CredentialRevocationRaceTest {

    private static final Logger log = LoggerFactory.getLogger(CredentialRevocationRaceTest.class);

    private final ManualClock clock = new ManualClock(1_000_000L);
    private final InMemoryCredentialStore credentialStore = new InMemoryCredentialStore();
    private final InMemoryAuthzStore authzStore = new InMemoryAuthzStore();
    private final InMemoryAuditService audit = new InMemoryAuditService();
    private final CredentialService credentialService =
            new CredentialServiceImpl(credentialStore, audit, clock);
    private final AccessServiceImpl accessService = new AccessServiceImpl(
            credentialService, credentialStore,
            new DefaultPolicyEvaluator(authzStore), audit, clock);

    @Test
    void revokedCredential_isAlwaysDenied_evenUnderConcurrentAccess() throws Exception {
        Credential c = credentialService.issue("dave", List.of("admin"), 600_000L);
        authzStore.upsertPolicy(new Policy("p-allow-admin", PolicyEffect.ALLOW,
                "docs/", "read", List.of("admin"), java.util.Map.of()));

        final int threads = 24;
        CyclicBarrier barrier = new CyclicBarrier(threads + 1);
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        ConcurrentLinkedQueue<Boolean> allows = new ConcurrentLinkedQueue<>();
        ConcurrentLinkedQueue<String> reasons = new ConcurrentLinkedQueue<>();
        CountDownLatch done = new CountDownLatch(threads);

        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    barrier.await();
                    try {
                        accessService.access(c.secret(), "docs/report", "read");
                        allows.add(true);
                        reasons.add("ALLOW");
                    } catch (IamException e) {
                        allows.add(false);
                        reasons.add(e.errorCode().name());
                    }
                } catch (Exception ignored) {
                    // 屏障中断等不参与判定统计
                } finally {
                    done.countDown();
                }
            });
        }
        barrier.await(); // 与工作线程同时释放
        credentialService.revoke(c.credentialId());
        assertThat(done.await(10, TimeUnit.SECONDS)).isTrue();
        pool.shutdownNow();

        long allowCount = allows.stream().filter(Boolean::booleanValue).count();
        log.info("input: credentialId={}, concurrentAccessThreads={}, revoke races with access",
                c.credentialId(), threads);
        log.info("basis: allowCount={}, denyReasons={}", allowCount, reasons);

        // 关键确定性：撤销一旦完成，后续绝无放行；撤销前已完成的请求可以放行，
        // 但绝不会出现“已撤销凭证仍被放行”。最终态必须抛出 REVOKED。
        ErrorCode finalReason = null;
        AuditEvent finalEvent = null;
        try {
            accessService.access(c.secret(), "docs/report", "read");
        } catch (IamException e) {
            finalReason = e.errorCode();
        }
        finalEvent = audit.findAll().stream()
                .filter(e -> e.operation().equals("ACCESS"))
                .reduce((a, b) -> b).orElse(null);
        log.info("post-revoke access reason={}, lastAuditOutcome={}", finalReason,
                finalEvent == null ? null : finalEvent.outcome());
        assertThat(finalReason).isEqualTo(ErrorCode.CREDENTIAL_REVOKED);
        assertThat(finalEvent).isNotNull();
        assertThat(finalEvent.outcome()).isEqualTo(AuditOutcome.DENIED_REVOKED);
    }

    @Test
    void revokeRacingWithRefresh_eitherRotateSucceedsOrRevokeWins_neverBoth() throws Exception {
        final int iterations = 200;
        int rotateWins = 0;
        int revokeWins = 0;
        for (int n = 0; n < iterations; n++) {
            Credential c = credentialService.issue("erin", List.of("reader"), 600_000L);
            CyclicBarrier barrier = new CyclicBarrier(2);
            ExecutorService pool = Executors.newFixedThreadPool(2);
            final boolean[] rotated = {false};
            final boolean[] revoked = {false};
            Runnable refreshTask = () -> {
                try {
                    barrier.await();
                    credentialService.refresh(c.secret());
                    rotated[0] = true;
                } catch (IamException e) {
                    // 预期为 REVOKED 或 CONFLICT
                } catch (Exception e) {
                    Thread.currentThread().interrupt();
                }
            };
            Runnable revokeTask = () -> {
                try {
                    barrier.await();
                    credentialService.revoke(c.credentialId());
                    revoked[0] = true;
                } catch (Exception e) {
                    Thread.currentThread().interrupt();
                }
            };
            pool.submit(refreshTask);
            pool.submit(revokeTask);
            pool.shutdown();
            assertThat(pool.awaitTermination(10, TimeUnit.SECONDS)).isTrue();

            // 最终态：凭证一定处于 REVOKED；轮换若发生，其新版本也必须已撤销且旧密文无效。
            Credential live = credentialStore.findById(c.credentialId()).view();
            assertThat(live.status().name()).isEqualTo("REVOKED");
            if (rotated[0]) {
                rotateWins++;
            }
            if (revoked[0]) {
                revokeWins++;
            }
            // 原密文若被轮换则 INVALID；若直接撤销则 REVOKED——两者都不允许放行。
            ErrorCode reason = null;
            try {
                accessService.access(c.secret(), "docs/x", "read");
            } catch (IamException e) {
                reason = e.errorCode();
            }
            assertThat(reason).isIn(ErrorCode.CREDENTIAL_REVOKED, ErrorCode.INVALID_CREDENTIAL);
        }
        log.info("input: {} iterations of revoke-vs-refresh race", iterations);
        log.info("basis: rotateHappened={}, revokeHappened={} (revoke always final)", rotateWins, revokeWins);
        assertThat(revokeWins).isEqualTo(iterations);
    }

    @Test
    void failureReasons_areDistinguishable_revoked_vs_expired_vs_invalid() {
        Credential revoked = credentialService.issue("frank", List.of(), 600_000L);
        credentialService.revoke(revoked.credentialId());
        assertThat(authenticateExpect(revoked.secret())).isEqualTo(ErrorCode.CREDENTIAL_REVOKED);

        Credential expired = credentialService.issue("grace", List.of(), 10_000L);
        clock.advance(10_001L);
        assertThat(authenticateExpect(expired.secret())).isEqualTo(ErrorCode.CREDENTIAL_EXPIRED);

        assertThat(authenticateExpect("tok_does_not_exist"))
                .isEqualTo(ErrorCode.INVALID_CREDENTIAL);

        Credential rotated = credentialService.issue("heidi", List.of(), 600_000L);
        Credential newer = credentialService.refresh(rotated.secret());
        // 旧密文因轮换立即无效；新密文仍有效。
        assertThat(authenticateExpect(rotated.secret())).isEqualTo(ErrorCode.INVALID_CREDENTIAL);
        assertThat(credentialService.authenticate(newer.secret()).credentialId())
                .isEqualTo(rotated.credentialId());

        log.info("basis: revoked->{}, expired->{}, missing->{}, rotatedOld->{}",
                ErrorCode.CREDENTIAL_REVOKED, ErrorCode.CREDENTIAL_EXPIRED,
                ErrorCode.INVALID_CREDENTIAL, ErrorCode.INVALID_CREDENTIAL);
    }

    @Test
    void revokeUnknownId_isDistinguishable() {
        ErrorCode code = null;
        try {
            credentialService.revoke("cred_unknown");
        } catch (IamException e) {
            code = e.errorCode();
        }
        assertThat(code).isEqualTo(ErrorCode.UNKNOWN_CREDENTIAL_ID);
    }

    private ErrorCode authenticateExpect(String secret) {
        try {
            credentialService.authenticate(secret);
            return null;
        } catch (IamException e) {
            return e.errorCode();
        }
    }
}
