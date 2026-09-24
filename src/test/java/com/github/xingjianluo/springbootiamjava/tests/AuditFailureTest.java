package com.github.xingjianluo.springbootiamjava.tests;

import static org.assertj.core.api.Assertions.assertThat;

import com.github.xingjianluo.springbootiamjava.iam.access.AccessResult;
import com.github.xingjianluo.springbootiamjava.iam.access.AccessServiceImpl;
import com.github.xingjianluo.springbootiamjava.iam.audit.AuditEvent;
import com.github.xingjianluo.springbootiamjava.iam.audit.AuditOutcome;
import com.github.xingjianluo.springbootiamjava.iam.audit.InMemoryAuditService;
import com.github.xingjianluo.springbootiamjava.iam.authz.DefaultPolicyEvaluator;
import com.github.xingjianluo.springbootiamjava.iam.authz.InMemoryAuthzStore;
import com.github.xingjianluo.springbootiamjava.iam.credential.CredentialServiceImpl;
import com.github.xingjianluo.springbootiamjava.iam.credential.InMemoryCredentialStore;
import com.github.xingjianluo.springbootiamjava.iam.error.ErrorCode;
import com.github.xingjianluo.springbootiamjava.iam.error.IamException;
import com.github.xingjianluo.springbootiamjava.iam.model.Credential;
import com.github.xingjianluo.springbootiamjava.iam.model.Policy;
import com.github.xingjianluo.springbootiamjava.iam.model.PolicyEffect;
import com.github.xingjianluo.springbootiamjava.tests.support.ManualClock;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 审计失败测试：审计不可写时受保护操作不得放行（失败关闭）；
 * 恢复后恢复放行；并发场景审计记录不丢失、事件 id 唯一，可还原判定依据。
 */
class AuditFailureTest {

    private static final Logger log = LoggerFactory.getLogger(AuditFailureTest.class);

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
                "docs/", "read", List.of("reader"), java.util.Map.of()));
    }

    @Test
    void whenAuditUnwritable_allowedRequest_isFailClosed() {
        seedAllowPolicy();
        Credential c = credentialService.issue("ivan", List.of("reader"), 600_000L);

        AccessResult ok = accessService.access(c.secret(), "docs/a", "read");
        assertThat(ok.allowed()).isTrue();

        audit.setWritable(false);
        log.info("input: audit set unwritable, subject=ivan otherwise allowed");
        ErrorCode blockedReason = null;
        try {
            accessService.access(c.secret(), "docs/b", "read");
        } catch (IamException e) {
            blockedReason = e.errorCode();
        }
        log.info("basis: reason={}, expected AUDIT_UNAVAILABLE", blockedReason);
        assertThat(blockedReason).isEqualTo(ErrorCode.AUDIT_UNAVAILABLE);

        // 恢复后立即恢复放行，且该凭证未被撤销
        audit.setWritable(true);
        AccessResult recovered = accessService.access(c.secret(), "docs/c", "read");
        assertThat(recovered.allowed()).isTrue();
    }

    @Test
    void whenAuditUnwritable_deniedRequest_remainsDeniedWithOriginalReason() {
        seedAllowPolicy();
        Credential c = credentialService.issue("judy", List.of(), 600_000L); // 无 reader 角色
        audit.setWritable(false);
        ErrorCode reason = null;
        try {
            accessService.access(c.secret(), "docs/a", "read");
        } catch (IamException e) {
            reason = e.errorCode();
        }
        log.info("input: no-role subject + audit unwritable -> basis: reason={}", reason);
        assertThat(reason).isEqualTo(ErrorCode.POLICY_DENIED);
    }

    @Test
    void concurrentAccess_recordsEveryDecision_withUniqueEventIds() throws Exception {
        seedAllowPolicy();
        final int threads = 32;
        Credential c = credentialService.issue("kyle", List.of("reader"), 600_000L);
        CyclicBarrier barrier = new CyclicBarrier(threads);
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch done = new CountDownLatch(threads);
        ConcurrentHashMap<String, byte[]> uniqueIds = new ConcurrentHashMap<>();
        int allowed = 0;
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    barrier.await();
                    AccessResult r = accessService.access(c.secret(), "docs/concurrent", "read");
                    if (r.allowed()) {
                        uniqueIds.put(r.auditEvent().eventId(), new byte[0]);
                    }
                } catch (Exception e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }
        assertThat(done.await(10, TimeUnit.SECONDS)).isTrue();
        pool.shutdownNow();

        // ISSUE 事件 1 条 + ACCESS ALLOW 事件 32 条
        List<AuditEvent> events = audit.findAll();
        long accessAllows = events.stream()
                .filter(e -> e.operation().equals("ACCESS") && e.outcome() == AuditOutcome.ALLOW)
                .count();
        long distinctAccessIds = events.stream()
                .filter(e -> e.operation().equals("ACCESS"))
                .map(AuditEvent::eventId).distinct().count();
        log.info("input: {} concurrent allowed accesses", threads);
        log.info("basis: accessAllowEvents={}, distinctAccessEventIds={}, totalEvents={}",
                accessAllows, distinctAccessIds, events.size());
        assertThat(accessAllows).isEqualTo(threads);
        assertThat(distinctAccessIds).isEqualTo(threads);
        assertThat(uniqueIds).hasSize(threads);

        // 审计记录可还原判定依据：含命中策略、修订号、凭证版本
        AuditEvent sample = events.stream()
                .filter(e -> e.operation().equals("ACCESS")).findFirst().orElseThrow();
        assertThat(sample.decisionDetail()).contains("matchedPolicies=[p-allow]");
        assertThat(sample.subject()).isEqualTo("kyle");
        assertThat(sample.credentialId()).isEqualTo(c.credentialId());
    }

    @Test
    void auditEvents_areImmutableAndAppendOnly() {
        seedAllowPolicy();
        Credential c = credentialService.issue("leo", List.of("reader"), 600_000L);
        accessService.access(c.secret(), "docs/a", "read");
        List<AuditEvent> snapshot = audit.findAll();
        int size = snapshot.size();
        // 返回的是防御性拷贝，调用方无法篡改审计
        try {
            snapshot.add(new AuditEvent(UUID.randomUUID().toString(), 1, "X", null, null,
                    null, null, AuditOutcome.ALLOW, "X", "X", 0));
        } catch (UnsupportedOperationException expected) {
            // expected
        }
        assertThat(audit.findAll()).hasSize(size);
        log.info("basis: audit trail append-only & immutable, size stays {}", size);
    }
}
