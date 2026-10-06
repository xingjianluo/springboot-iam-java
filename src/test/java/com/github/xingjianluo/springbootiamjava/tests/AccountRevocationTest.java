package com.github.xingjianluo.springbootiamjava.tests;

import static org.assertj.core.api.Assertions.assertThat;

import com.github.xingjianluo.springbootiamjava.iam.access.AccessServiceImpl;
import com.github.xingjianluo.springbootiamjava.iam.audit.AuditEvent;
import com.github.xingjianluo.springbootiamjava.iam.audit.InMemoryAuditService;
import com.github.xingjianluo.springbootiamjava.iam.authz.DefaultPolicyEvaluator;
import com.github.xingjianluo.springbootiamjava.iam.authz.InMemoryAuthzStore;
import com.github.xingjianluo.springbootiamjava.iam.credential.AccountSessionSummary;
import com.github.xingjianluo.springbootiamjava.iam.credential.BulkRevokeResult;
import com.github.xingjianluo.springbootiamjava.iam.credential.CredentialServiceImpl;
import com.github.xingjianluo.springbootiamjava.iam.credential.InMemoryCredentialStore;
import com.github.xingjianluo.springbootiamjava.iam.error.ErrorCode;
import com.github.xingjianluo.springbootiamjava.iam.error.IamException;
import com.github.xingjianluo.springbootiamjava.iam.model.Credential;
import com.github.xingjianluo.springbootiamjava.iam.model.Policy;
import com.github.xingjianluo.springbootiamjava.iam.model.PolicyEffect;
import com.github.xingjianluo.springbootiamjava.tests.support.ManualClock;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 账号级凭证治理测试：一键吊销某账号全部登录 + 会话汇总。
 *
 * <p>覆盖：批量吊销含刷新派生后代、已过期/已吊销的识别、重复执行稳定、
 * 无有效凭证与系统不可用可区分、审计失败整体回退、与并发刷新/并发访问交错时的确定性。
 */
class AccountRevocationTest {

    private static final Logger log = LoggerFactory.getLogger(AccountRevocationTest.class);

    private final ManualClock clock = new ManualClock(1_000_000L);
    private final InMemoryCredentialStore credentialStore = new InMemoryCredentialStore();
    private final InMemoryAuthzStore authzStore = new InMemoryAuthzStore();
    private final InMemoryAuditService audit = new InMemoryAuditService();
    private final CredentialServiceImpl credentialService =
            new CredentialServiceImpl(credentialStore, audit, clock);
    private final AccessServiceImpl accessService = new AccessServiceImpl(
            credentialService, credentialStore,
            new DefaultPolicyEvaluator(authzStore), audit, clock);

    private void seedAllowPolicy() {
        authzStore.upsertPolicy(new Policy("p-allow", PolicyEffect.ALLOW,
                "docs/", "read", List.of("reader"), Map.of()));
    }

    private ErrorCode authenticateExpect(String secret) {
        try {
            credentialService.authenticate(secret);
            return null;
        } catch (IamException e) {
            return e.errorCode();
        }
    }

    private ErrorCode accessExpect(String secret) {
        try {
            accessService.access(secret, "docs/a", "read");
            return null;
        } catch (IamException e) {
            return e.errorCode();
        }
    }

    @Test
    void revokeAll_revokesEveryActiveCredential_includingRotatedDescendants() {
        Credential first = credentialService.issue("alice", List.of("reader"), 600_000L);
        Credential second = credentialService.issue("alice", List.of("reader"), 600_000L);
        // 第一条凭证链刷新两代：后代与祖先共用 credentialId。
        Credential gen1 = credentialService.refresh(first.secret());
        Credential gen2 = credentialService.refresh(gen1.secret());
        Credential other = credentialService.issue("bob", List.of("reader"), 600_000L);

        BulkRevokeResult result = credentialService.revokeAllForSubject("alice");
        log.info("input: subject=alice, credentials=[{}(rotated x2), {}]", 
                first.credentialId(), second.credentialId());
        log.info("basis: revoked={}, alreadyRevoked={}, expired={}, epoch={}",
                result.revokedCredentialIds(), result.alreadyRevokedCredentialIds(),
                result.expiredCredentialIds(), result.revocationEpoch());

        assertThat(result.status()).isEqualTo(BulkRevokeResult.Status.SUCCESS);
        assertThat(result.revokedCredentialIds())
                .containsExactlyInAnyOrder(first.credentialId(), second.credentialId());
        assertThat(result.alreadyRevokedCredentialIds()).isEmpty();
        assertThat(result.expiredCredentialIds()).isEmpty();
        assertThat(result.revocationEpoch()).isEqualTo(1L);

        // 链上每一代密文都不得再被放行：当前代 -> REVOKED；被轮换的旧代 -> INVALID。
        assertThat(authenticateExpect(gen2.secret())).isEqualTo(ErrorCode.CREDENTIAL_REVOKED);
        assertThat(authenticateExpect(gen1.secret())).isEqualTo(ErrorCode.INVALID_CREDENTIAL);
        assertThat(authenticateExpect(first.secret())).isEqualTo(ErrorCode.INVALID_CREDENTIAL);
        assertThat(authenticateExpect(second.secret())).isEqualTo(ErrorCode.CREDENTIAL_REVOKED);
        // 已吊销凭证不可能被刷新重新续出有效凭证。
        assertThat(refreshExpect(gen2.secret())).isEqualTo(ErrorCode.CREDENTIAL_REVOKED);
        // 其他账号不受影响。
        assertThat(authenticateExpect(other.secret())).isNull();

        AccountSessionSummary summary = credentialService.sessionsOf("alice");
        assertThat(summary.activeCount()).isZero();
        assertThat(summary.revocationEpoch()).isEqualTo(1L);
        log.info("post-revoke summary: activeCount={}, epoch={}",
                summary.activeCount(), summary.revocationEpoch());
    }

    private ErrorCode refreshExpect(String secret) {
        try {
            credentialService.refresh(secret);
            return null;
        } catch (IamException e) {
            return e.errorCode();
        }
    }

    @Test
    void revokeAll_identifiesExpiredAndAlreadyRevoked_notMissedNotFalsePositive() {
        Credential active = credentialService.issue("carol", List.of(), 600_000L);
        Credential willExpire = credentialService.issue("carol", List.of(), 10_000L);
        Credential willRevoke = credentialService.issue("carol", List.of(), 600_000L);
        credentialService.revoke(willRevoke.credentialId());
        clock.advance(10_001L); // willExpire 过期

        BulkRevokeResult result = credentialService.revokeAllForSubject("carol");
        log.info("input: subject=carol, active={}, expired={}, alreadyRevoked={}",
                active.credentialId(), willExpire.credentialId(), willRevoke.credentialId());
        log.info("basis: revoked={}, alreadyRevoked={}, expired={}",
                result.revokedCredentialIds(), result.alreadyRevokedCredentialIds(),
                result.expiredCredentialIds());

        assertThat(result.status()).isEqualTo(BulkRevokeResult.Status.SUCCESS);
        assertThat(result.revokedCredentialIds()).containsExactly(active.credentialId());
        assertThat(result.expiredCredentialIds()).containsExactly(willExpire.credentialId());
        assertThat(result.alreadyRevokedCredentialIds()).containsExactly(willRevoke.credentialId());
        // 已过期/已吊销的密文原因码保持可区分，不被批量吊销误改。
        assertThat(authenticateExpect(willExpire.secret())).isEqualTo(ErrorCode.CREDENTIAL_EXPIRED);
        assertThat(authenticateExpect(willRevoke.secret())).isEqualTo(ErrorCode.CREDENTIAL_REVOKED);
    }

    @Test
    void revokeAll_isRepeatable_withStableState() {
        Credential c1 = credentialService.issue("dave", List.of(), 600_000L);
        Credential c2 = credentialService.issue("dave", List.of(), 600_000L);

        BulkRevokeResult first = credentialService.revokeAllForSubject("dave");
        BulkRevokeResult second = credentialService.revokeAllForSubject("dave");
        log.info("input: subject=dave revoked twice");
        log.info("basis: first revoked={}, epoch={}; second revoked={}, alreadyRevoked={}, epoch={}",
                first.revokedCredentialIds(), first.revocationEpoch(),
                second.revokedCredentialIds(), second.alreadyRevokedCredentialIds(),
                second.revocationEpoch());

        assertThat(first.status()).isEqualTo(BulkRevokeResult.Status.SUCCESS);
        assertThat(first.revokedCredentialIds()).hasSize(2);
        // 重复执行：整体成功、本次无新增吊销、两条都被识别为“之前已吊销”，状态稳定。
        assertThat(second.status()).isEqualTo(BulkRevokeResult.Status.SUCCESS);
        assertThat(second.revokedCredentialIds()).isEmpty();
        assertThat(second.alreadyRevokedCredentialIds())
                .containsExactlyInAnyOrder(c1.credentialId(), c2.credentialId());
        assertThat(second.revocationEpoch()).isEqualTo(first.revocationEpoch() + 1);
        assertThat(authenticateExpect(c1.secret())).isEqualTo(ErrorCode.CREDENTIAL_REVOKED);
        assertThat(authenticateExpect(c2.secret())).isEqualTo(ErrorCode.CREDENTIAL_REVOKED);
        assertThat(credentialService.sessionsOf("dave").activeCount()).isZero();
    }

    @Test
    void revokeAll_noCredentials_isDistinguishableFromSystemFailure() {
        ErrorCode noCreds = null;
        try {
            credentialService.revokeAllForSubject("nobody");
        } catch (IamException e) {
            noCreds = e.errorCode();
        }
        credentialService.issue("erin", List.of(), 600_000L);
        audit.setWritable(false);
        ErrorCode systemDown = null;
        try {
            credentialService.revokeAllForSubject("erin");
        } catch (IamException e) {
            systemDown = e.errorCode();
        }
        audit.setWritable(true);
        log.info("input: unknown subject vs audit-unwritable subject");
        log.info("basis: noCredentials->{}, auditDown->{} (must differ)", noCreds, systemDown);

        assertThat(noCreds).isEqualTo(ErrorCode.NO_ACTIVE_CREDENTIALS);
        assertThat(systemDown).isEqualTo(ErrorCode.AUDIT_UNAVAILABLE);
        assertThat(noCreds).isNotEqualTo(systemDown);
    }

    @Test
    void revokeAll_auditUnavailable_failsAtomicallyWithoutPartialState() {
        Credential c1 = credentialService.issue("frank", List.of("reader"), 600_000L);
        Credential c2 = credentialService.issue("frank", List.of("reader"), 600_000L);
        int issueEvents = audit.findAll().size();

        audit.setWritable(false);
        ErrorCode reason = null;
        try {
            credentialService.revokeAllForSubject("frank");
        } catch (IamException e) {
            reason = e.errorCode();
        }
        log.info("input: subject=frank with 2 active credentials, audit unwritable");
        log.info("basis: reason={}, summaryAfterFailure={}",
                reason, credentialService.sessionsOf("frank"));

        assertThat(reason).isEqualTo(ErrorCode.AUDIT_UNAVAILABLE);
        // 整体失败：两条凭证都仍然有效，不存在“吊销了一半”的中间态；代次不变。
        AccountSessionSummary afterFailure = credentialService.sessionsOf("frank");
        assertThat(afterFailure.activeCount()).isEqualTo(2);
        assertThat(afterFailure.revocationEpoch()).isZero();
        assertThat(authenticateExpect(c1.secret())).isNull();
        assertThat(authenticateExpect(c2.secret())).isNull();
        // 审计不可写期间没有留下任何 REVOKE_ALL 记录。
        assertThat(audit.findAll()).hasSize(issueEvents);

        // 恢复后重试成功：整体吊销，代次 +1，审计链可还原。
        audit.setWritable(true);
        BulkRevokeResult retry = credentialService.revokeAllForSubject("frank");
        assertThat(retry.status()).isEqualTo(BulkRevokeResult.Status.SUCCESS);
        assertThat(retry.revokedCredentialIds())
                .containsExactlyInAnyOrder(c1.credentialId(), c2.credentialId());
        assertThat(retry.revocationEpoch()).isEqualTo(1L);
        AuditEvent revokeAllEvent = audit.findAll().stream()
                .filter(e -> e.operation().equals("REVOKE_ALL"))
                .reduce((a, b) -> b).orElseThrow();
        assertThat(revokeAllEvent.subject()).isEqualTo("frank");
        assertThat(revokeAllEvent.decisionDetail()).contains(c1.credentialId());
        assertThat(revokeAllEvent.decisionDetail()).contains("revocationEpoch=1");
        log.info("basis: retry committed, auditEvent={}", revokeAllEvent.decisionDetail());
    }

    @Test
    void revokeAll_racingWithRefresh_neverReextendsRevokedCredential() throws Exception {
        final int iterations = 200;
        int rotateBeforeRevoke = 0;
        for (int n = 0; n < iterations; n++) {
            String subject = "grace-" + n; // 每轮独立账号，避免历史凭证跨轮累积
            Credential c = credentialService.issue(subject, List.of(), 600_000L);
            CyclicBarrier barrier = new CyclicBarrier(2);
            ExecutorService pool = Executors.newFixedThreadPool(2);
            final Credential[] rotated = new Credential[1];
            Runnable refreshTask = () -> {
                try {
                    barrier.await();
                    rotated[0] = credentialService.refresh(c.secret());
                } catch (IamException expected) {
                    // 吊销在前 -> REVOKED
                } catch (Exception e) {
                    Thread.currentThread().interrupt();
                }
            };
            Runnable revokeTask = () -> {
                try {
                    barrier.await();
                    credentialService.revokeAllForSubject(subject);
                } catch (Exception e) {
                    Thread.currentThread().interrupt();
                }
            };
            pool.submit(refreshTask);
            pool.submit(revokeTask);
            pool.shutdown();
            assertThat(pool.awaitTermination(10, TimeUnit.SECONDS)).isTrue();

            // 最终态确定：凭证链一定 REVOKED；即使轮换先发生，新密文也一并被吊销。
            assertThat(credentialStore.findById(c.credentialId()).view().status().name())
                    .isEqualTo("REVOKED");
            if (rotated[0] != null) {
                rotateBeforeRevoke++;
                assertThat(authenticateExpect(rotated[0].secret()))
                        .isEqualTo(ErrorCode.CREDENTIAL_REVOKED);
                // 已被吊销的凭证不可能被一次刷新重新续出有效凭证。
                assertThat(refreshExpect(rotated[0].secret()))
                        .isEqualTo(ErrorCode.CREDENTIAL_REVOKED);
            } else {
                assertThat(refreshExpect(c.secret())).isEqualTo(ErrorCode.CREDENTIAL_REVOKED);
            }
            assertThat(credentialService.sessionsOf(subject).activeCount()).isZero();
        }
        log.info("input: {} iterations of revokeAll-vs-refresh race", iterations);
        log.info("basis: rotateHappenedBeforeRevoke={} (final state always REVOKED, activeCount=0)",
                rotateBeforeRevoke);
    }

    @Test
    void revokeAll_racingWithAccess_noCredentialAllowedAfterReturn() throws Exception {
        seedAllowPolicy();
        Credential c1 = credentialService.issue("heidi", List.of("reader"), 600_000L);
        Credential c2 = credentialService.issue("heidi", List.of("reader"), 600_000L);
        List<String> secrets = List.of(c1.secret(), c2.secret());

        final int threads = 16;
        CyclicBarrier barrier = new CyclicBarrier(threads + 1);
        AtomicBoolean stop = new AtomicBoolean(false);
        ConcurrentLinkedQueue<String> outcomes = new ConcurrentLinkedQueue<>();
        CountDownLatch done = new CountDownLatch(threads);
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        for (int i = 0; i < threads; i++) {
            final String secret = secrets.get(i % secrets.size());
            pool.submit(() -> {
                try {
                    barrier.await();
                    while (!stop.get()) {
                        ErrorCode code = accessExpect(secret);
                        outcomes.add(code == null ? "ALLOW" : code.name());
                    }
                } catch (Exception ignored) {
                    // 屏障中断等不参与统计
                } finally {
                    done.countDown();
                }
            });
        }
        barrier.await();
        BulkRevokeResult result = credentialService.revokeAllForSubject("heidi");
        // 操作返回之后：该账号任何凭证的新访问都必须被拒绝（REVOKED），无一例外。
        for (String secret : secrets) {
            assertThat(accessExpect(secret)).isEqualTo(ErrorCode.CREDENTIAL_REVOKED);
        }
        stop.set(true);
        assertThat(done.await(10, TimeUnit.SECONDS)).isTrue();
        pool.shutdownNow();

        log.info("input: subject=heidi, {} concurrent access threads racing revokeAll", threads);
        log.info("basis: revoked={}, epoch={}, sampleOutcomes={}",
                result.revokedCredentialIds(), result.revocationEpoch(),
                outcomes.stream().limit(20).toList());
        assertThat(result.status()).isEqualTo(BulkRevokeResult.Status.SUCCESS);
        assertThat(result.revokedCredentialIds())
                .containsExactlyInAnyOrder(c1.credentialId(), c2.credentialId());
        assertThat(credentialService.sessionsOf("heidi").activeCount()).isZero();
        // 返回后的审计结论中不存在对该账号的 ALLOW。
        long allowsAfterRevoke = audit.findAll().stream()
                .filter(e -> e.operation().equals("ACCESS"))
                .filter(e -> e.timestampMillis() >= 0 && "heidi".equals(e.subject()))
                .filter(e -> e.outcome() == com.github.xingjianluo.springbootiamjava.iam.audit.AuditOutcome.ALLOW)
                .count();
        log.info("basis: totalAllowEventsForHeidi={} (all linearized before revoke commit)",
                allowsAfterRevoke);
    }

    @Test
    void sessionSummary_listsOnlyActiveSessions_withIdentifiableEpoch() {
        Credential active1 = credentialService.issue("ivan", List.of(), 600_000L);
        Credential active2 = credentialService.issue("ivan", List.of(), 600_000L);
        Credential expired = credentialService.issue("ivan", List.of(), 5_000L);
        Credential revoked = credentialService.issue("ivan", List.of(), 600_000L);
        credentialService.revoke(revoked.credentialId());
        // 历史累积：ivan 名下还有大量已轮换的旧链，不影响汇总结果大小。
        Credential chain = credentialService.issue("ivan", List.of(), 600_000L);
        Credential latest = chain;
        for (int i = 0; i < 50; i++) {
            latest = credentialService.refresh(latest.secret());
        }
        clock.advance(5_001L); // expired 过期

        AccountSessionSummary summary = credentialService.sessionsOf("ivan");
        log.info("input: subject=ivan with active x3 (incl. 50-generation chain), expired x1, revoked x1");
        log.info("basis: activeCount={}, sessions={}, epoch={}",
                summary.activeCount(), summary.sessions(), summary.revocationEpoch());

        // 只含当前有效会话：active1、active2、轮换链的最新一代（同一 credentialId）。
        assertThat(summary.activeCount()).isEqualTo(3);
        assertThat(summary.sessions())
                .extracting(AccountSessionSummary.SessionEntry::credentialId)
                .containsExactlyInAnyOrder(active1.credentialId(), active2.credentialId(),
                        chain.credentialId());
        assertThat(summary.sessions())
                .extracting(AccountSessionSummary.SessionEntry::credentialId)
                .doesNotContain(expired.credentialId(), revoked.credentialId());
        assertThat(summary.revocationEpoch()).isZero();

        // 批量吊销后汇总收敛：activeCount=0，代次与吊销返回一致，可据此确认处置完成。
        BulkRevokeResult result = credentialService.revokeAllForSubject("ivan");
        AccountSessionSummary converged = credentialService.sessionsOf("ivan");
        log.info("basis: after revokeAll epoch={} -> summary activeCount={}, epoch={}",
                result.revocationEpoch(), converged.activeCount(), converged.revocationEpoch());
        assertThat(converged.activeCount()).isZero();
        assertThat(converged.sessions()).isEmpty();
        assertThat(converged.revocationEpoch()).isEqualTo(result.revocationEpoch());
    }
}
