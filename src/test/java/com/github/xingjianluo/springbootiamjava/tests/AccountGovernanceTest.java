package com.github.xingjianluo.springbootiamjava.tests;

import static org.assertj.core.api.Assertions.assertThat;

import com.github.xingjianluo.springbootiamjava.iam.access.AccessServiceImpl;
import com.github.xingjianluo.springbootiamjava.iam.account.AccountGovernanceServiceImpl;
import com.github.xingjianluo.springbootiamjava.iam.account.BatchRevocationResult;
import com.github.xingjianluo.springbootiamjava.iam.account.SessionSummary;
import com.github.xingjianluo.springbootiamjava.iam.audit.AuditEvent;
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
import java.util.Map;
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
 * 账号级凭证治理测试：一键结束全部登录（批量吊销）与会话汇总。
 *
 * <p>覆盖：批量吊销与并发刷新/并发访问交错的确定性、重复吊销、无有效凭证、
 * 审计不可用整体失败、刷新派生的后代凭证一并终止、会话汇总收敛确认。
 */
class AccountGovernanceTest {

    private static final Logger log = LoggerFactory.getLogger(AccountGovernanceTest.class);

    private final ManualClock clock = new ManualClock(1_000_000L);
    private final InMemoryCredentialStore credentialStore = new InMemoryCredentialStore();
    private final InMemoryAuthzStore authzStore = new InMemoryAuthzStore();
    private final InMemoryAuditService audit = new InMemoryAuditService();
    private final CredentialService credentialService =
            new CredentialServiceImpl(credentialStore, audit, clock);
    private final AccessServiceImpl accessService = new AccessServiceImpl(
            credentialService, credentialStore,
            new DefaultPolicyEvaluator(authzStore), audit, clock);
    private final AccountGovernanceServiceImpl governance =
            new AccountGovernanceServiceImpl(credentialStore, audit, clock);

    private void allowDocsRead(String role) {
        authzStore.upsertPolicy(new Policy("p-allow-" + role, PolicyEffect.ALLOW,
                "docs/", "read", List.of(role), Map.of()));
    }

    private ErrorCode accessExpect(String secret) {
        try {
            accessService.access(secret, "docs/report", "read");
            return null;
        } catch (IamException e) {
            return e.errorCode();
        }
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
    void revokeAll_terminatesAllActiveCredentials_includingRefreshDescendants() {
        allowDocsRead("reader");
        Credential c1 = credentialService.issue("ivy", List.of("reader"), 600_000L);
        Credential c2 = credentialService.issue("ivy", List.of("reader"), 600_000L);
        // c1 刷新两代，派生出后代凭证（同一 credentialId 链）。
        Credential c1v1 = credentialService.refresh(c1.secret());
        Credential c1v2 = credentialService.refresh(c1v1.secret());
        // 已过期与已吊销的凭证应被识别，不算漏网。
        Credential expired = credentialService.issue("ivy", List.of("reader"), 5_000L);
        Credential preRevoked = credentialService.issue("ivy", List.of("reader"), 600_000L);
        credentialService.revoke(preRevoked.credentialId());
        clock.advance(6_000L); // expired 现已过期，其余仍有效

        SessionSummary before = governance.sessionsOf("ivy");
        log.info("input: subject=ivy, activeSessionsBefore={}, ids={}",
                before.activeCount(),
                before.sessions().stream().map(s -> s.credentialId() + "@v" + s.version()).toList());
        // 有效的是 c1 链（当前 c1v2）与 c2；preRevoked 已吊销、expired 已过期，不计入。
        assertThat(before.activeCount()).isEqualTo(2);

        BatchRevocationResult result = governance.revokeAllForSubject("ivy");
        log.info("basis: operationId={}, revokedCount={}, alreadyRevoked={}, expired={}, revokedIds={}",
                result.operationId(), result.revokedCount(), result.alreadyRevokedCount(),
                result.expiredCount(), result.revokedCredentialIds());

        assertThat(result.revokedCount()).isEqualTo(2);
        assertThat(result.revokedCredentialIds())
                .containsExactlyInAnyOrder(c1.credentialId(), c2.credentialId());
        assertThat(result.alreadyRevokedCount()).isEqualTo(1);
        assertThat(result.expiredCount()).isEqualTo(1);

        // 操作返回后：该账号任何密文（含刷新派生的最新密文）都不能再访问、不能再刷新续期。
        assertThat(accessExpect(c1v2.secret())).isEqualTo(ErrorCode.CREDENTIAL_REVOKED);
        assertThat(accessExpect(c2.secret())).isEqualTo(ErrorCode.CREDENTIAL_REVOKED);
        assertThat(refreshExpect(c1v2.secret())).isEqualTo(ErrorCode.CREDENTIAL_REVOKED);
        assertThat(refreshExpect(c2.secret())).isEqualTo(ErrorCode.CREDENTIAL_REVOKED);

        SessionSummary after = governance.sessionsOf("ivy");
        log.info("converged: activeSessionsAfter={}", after.activeCount());
        assertThat(after.activeCount()).isZero();

        // 审计链中有本次批量操作，operationId 可对应。
        AuditEvent batchEvent = audit.findAll().stream()
                .filter(e -> e.operation().equals("REVOKE_ALL"))
                .reduce((a, b) -> b).orElseThrow();
        assertThat(batchEvent.subject()).isEqualTo("ivy");
        assertThat(batchEvent.decisionDetail()).contains(result.operationId());
    }

    @Test
    void revokeAll_racingWithConcurrentRefresh_neverLeavesUsableCredential() throws Exception {
        final int iterations = 100;
        int refreshWon = 0;
        int refreshRejected = 0;
        for (int n = 0; n < iterations; n++) {
            Credential c = credentialService.issue("judy", List.of("reader"), 600_000L);
            CyclicBarrier barrier = new CyclicBarrier(2);
            ExecutorService pool = Executors.newFixedThreadPool(2);
            final String[] refreshedSecret = {null};
            final ErrorCode[] refreshError = {null};
            pool.submit(() -> {
                try {
                    barrier.await();
                    refreshedSecret[0] = credentialService.refresh(c.secret()).secret();
                } catch (IamException e) {
                    refreshError[0] = e.errorCode();
                } catch (Exception e) {
                    Thread.currentThread().interrupt();
                }
            });
            final BatchRevocationResult[] result = {null};
            pool.submit(() -> {
                try {
                    barrier.await();
                    result[0] = governance.revokeAllForSubject("judy");
                } catch (IamException e) {
                    // 若刷新先完成，批量吊销仍会吊销新版本，不会走到这里；
                    // 这里兜底记录，断言见下方。
                } catch (Exception e) {
                    Thread.currentThread().interrupt();
                }
            });
            pool.shutdown();
            assertThat(pool.awaitTermination(10, TimeUnit.SECONDS)).isTrue();

            if (refreshedSecret[0] != null) {
                refreshWon++;
                // 刷新即使在交错中成功，批量吊销返回后新密文也必须已失效：
                // 要么被同一次批量吊销覆盖（同 credentialId 链），要么判定为已撤销。
                assertThat(accessExpect(refreshedSecret[0]))
                        .isIn(ErrorCode.CREDENTIAL_REVOKED, ErrorCode.INVALID_CREDENTIAL);
                assertThat(refreshExpect(refreshedSecret[0]))
                        .isIn(ErrorCode.CREDENTIAL_REVOKED, ErrorCode.INVALID_CREDENTIAL,
                                ErrorCode.REFRESH_CONFLICT);
            } else {
                refreshRejected++;
                assertThat(refreshError[0]).isEqualTo(ErrorCode.CREDENTIAL_REVOKED);
            }
            // 最终态：该账号会话清零，原密文绝不可用。
            assertThat(governance.sessionsOf("judy").activeCount()).isZero();
            assertThat(accessExpect(c.secret()))
                    .isIn(ErrorCode.CREDENTIAL_REVOKED, ErrorCode.INVALID_CREDENTIAL);
            credentialStore.clear();
        }
        log.info("input: {} iterations of revoke-all-vs-refresh race", iterations);
        log.info("basis: refreshWonBeforeRevokeAll={}, refreshRejectedAsRevoked={}; "
                + "post-op sessions always 0", refreshWon, refreshRejected);
    }

    @Test
    void revokeAll_racingWithConcurrentAccess_noAccessAllowedAfterReturn() throws Exception {
        allowDocsRead("reader");
        Credential c1 = credentialService.issue("karl", List.of("reader"), 600_000L);
        Credential c2 = credentialService.issue("karl", List.of("reader"), 600_000L);

        final int threads = 16;
        CyclicBarrier barrier = new CyclicBarrier(threads + 1);
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        ConcurrentLinkedQueue<String> outcomes = new ConcurrentLinkedQueue<>();
        CountDownLatch done = new CountDownLatch(threads);
        for (int i = 0; i < threads; i++) {
            String secret = (i % 2 == 0) ? c1.secret() : c2.secret();
            pool.submit(() -> {
                try {
                    barrier.await();
                    ErrorCode err = accessExpect(secret);
                    outcomes.add(err == null ? "ALLOW" : err.name());
                } catch (Exception ignored) {
                    // 屏障中断等不参与统计
                } finally {
                    done.countDown();
                }
            });
        }
        barrier.await();
        BatchRevocationResult result = governance.revokeAllForSubject("karl");
        assertThat(done.await(10, TimeUnit.SECONDS)).isTrue();
        pool.shutdownNow();

        long allows = outcomes.stream().filter("ALLOW"::equals).count();
        log.info("input: subject=karl, credentials=2, concurrentAccessThreads={}, revoke-all races",
                threads);
        log.info("basis: operationId={}, allowsDuringRace={}, outcomes={}",
                result.operationId(), allows, outcomes);

        // 确定性：批量吊销返回之后，该账号任何凭证都不再放行。
        assertThat(accessExpect(c1.secret())).isEqualTo(ErrorCode.CREDENTIAL_REVOKED);
        assertThat(accessExpect(c2.secret())).isEqualTo(ErrorCode.CREDENTIAL_REVOKED);
        assertThat(governance.sessionsOf("karl").activeCount()).isZero();
    }

    @Test
    void revokeAll_isRepeatable_secondCallReportsNoActiveCredentials() {
        credentialService.issue("liam", List.of(), 600_000L);
        credentialService.issue("liam", List.of(), 600_000L);

        BatchRevocationResult first = governance.revokeAllForSubject("liam");
        assertThat(first.revokedCount()).isEqualTo(2);

        ErrorCode second = null;
        try {
            governance.revokeAllForSubject("liam");
        } catch (IamException e) {
            second = e.errorCode();
        }
        log.info("input: repeat revoke-all for liam | basis: first={}, second={}",
                first.revokedCount(), second);
        // 重复执行结果稳定：状态不再变化，反馈为可区分的“没有有效凭证”。
        assertThat(second).isEqualTo(ErrorCode.NO_ACTIVE_CREDENTIALS);
        assertThat(governance.sessionsOf("liam").activeCount()).isZero();

        ErrorCode third = null;
        try {
            governance.revokeAllForSubject("liam");
        } catch (IamException e) {
            third = e.errorCode();
        }
        assertThat(third).isEqualTo(ErrorCode.NO_ACTIVE_CREDENTIALS);
    }

    @Test
    void revokeAll_withNoActiveCredentials_isDistinguishableFromSystemFailure() {
        // 场景一：账号从未有凭证。
        assertThat(revokeAllExpect("nobody")).isEqualTo(ErrorCode.NO_ACTIVE_CREDENTIALS);

        // 场景二：凭证全部已过期。
        credentialService.issue("olga", List.of(), 5_000L);
        clock.advance(6_000L);
        assertThat(revokeAllExpect("olga")).isEqualTo(ErrorCode.NO_ACTIVE_CREDENTIALS);

        // 场景三：凭证全部已吊销。
        Credential c = credentialService.issue("pat", List.of(), 600_000L);
        credentialService.revoke(c.credentialId());
        assertThat(revokeAllExpect("pat")).isEqualTo(ErrorCode.NO_ACTIVE_CREDENTIALS);

        // 场景四：审计不可用 -> 系统侧失败，原因码与上面三类完全不同。
        credentialService.issue("quinn", List.of(), 600_000L);
        audit.setWritable(false);
        ErrorCode systemFailure = revokeAllExpect("quinn");
        audit.setWritable(true);
        log.info("basis: noCredential/expired/revoked -> {}, auditDown -> {}",
                ErrorCode.NO_ACTIVE_CREDENTIALS, systemFailure);
        assertThat(systemFailure).isEqualTo(ErrorCode.AUDIT_UNAVAILABLE);
        assertThat(systemFailure).isNotEqualTo(ErrorCode.NO_ACTIVE_CREDENTIALS);
    }

    @Test
    void revokeAll_failsAtomically_whenAuditUnavailable() {
        allowDocsRead("reader");
        Credential c1 = credentialService.issue("ruth", List.of("reader"), 600_000L);
        Credential c2 = credentialService.issue("ruth", List.of("reader"), 600_000L);

        audit.setWritable(false);
        ErrorCode err = revokeAllExpect("ruth");
        audit.setWritable(true);
        log.info("input: revoke-all with audit down | basis: error={}", err);
        assertThat(err).isEqualTo(ErrorCode.AUDIT_UNAVAILABLE);

        // 整体失败：不能留下“吊销一半”的中间态——两个凭证都必须仍然有效。
        SessionSummary summary = governance.sessionsOf("ruth");
        log.info("post-failure: activeSessions={}", summary.activeCount());
        assertThat(summary.activeCount()).isEqualTo(2);
        assertThat(accessExpect(c1.secret())).isNull();
        assertThat(accessExpect(c2.secret())).isNull();

        // 审计恢复后重试成功，且只吊销一次（结果稳定收敛）。
        BatchRevocationResult retry = governance.revokeAllForSubject("ruth");
        assertThat(retry.revokedCount()).isEqualTo(2);
        assertThat(governance.sessionsOf("ruth").activeCount()).isZero();
    }

    @Test
    void sessionSummary_identifiesActiveSessions_andDoesNotBlockLifecycle() throws Exception {
        allowDocsRead("reader");
        Credential c1 = credentialService.issue("sara", List.of("reader"), 600_000L);
        Credential c2 = credentialService.issue("sara", List.of("reader"), 600_000L);
        Credential c2v1 = credentialService.refresh(c2.secret());

        SessionSummary summary = governance.sessionsOf("sara");
        log.info("input: subject=sara | basis: activeCount={}, sessions={}",
                summary.activeCount(),
                summary.sessions().stream().map(s -> s.credentialId() + "@v" + s.version()).toList());
        assertThat(summary.activeCount()).isEqualTo(2);
        // 可辨识标识：credentialId + version；c2 链当前版本为 1。
        assertThat(summary.sessions())
                .anySatisfy(s -> {
                    assertThat(s.credentialId()).isEqualTo(c2.credentialId());
                    assertThat(s.version()).isEqualTo(1L);
                })
                .anySatisfy(s -> assertThat(s.credentialId()).isEqualTo(c1.credentialId()));

        // 查询与并发访问/刷新交错时不阻塞、不报错。
        final int threads = 8;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch done = new CountDownLatch(threads);
        ConcurrentLinkedQueue<Throwable> errors = new ConcurrentLinkedQueue<>();
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    for (int k = 0; k < 50; k++) {
                        governance.sessionsOf("sara");
                        accessExpect(c1.secret());
                    }
                } catch (Throwable t) {
                    errors.add(t);
                } finally {
                    done.countDown();
                }
            });
        }
        assertThat(done.await(15, TimeUnit.SECONDS)).isTrue();
        pool.shutdownNow();
        assertThat(errors).isEmpty();
        // 刷新派生的新密文仍可用（查询不影响生命周期）。
        assertThat(accessExpect(c2v1.secret())).isNull();
    }

    private ErrorCode revokeAllExpect(String subject) {
        try {
            governance.revokeAllForSubject(subject);
            return null;
        } catch (IamException e) {
            return e.errorCode();
        }
    }
}
