package com.github.xingjianluo.springbootiamjava.tests;

import static org.assertj.core.api.Assertions.assertThat;

import com.github.xingjianluo.springbootiamjava.iam.audit.InMemoryAuditService;
import com.github.xingjianluo.springbootiamjava.iam.credential.CredentialService;
import com.github.xingjianluo.springbootiamjava.iam.credential.CredentialServiceImpl;
import com.github.xingjianluo.springbootiamjava.iam.credential.InMemoryCredentialStore;
import com.github.xingjianluo.springbootiamjava.iam.error.ErrorCode;
import com.github.xingjianluo.springbootiamjava.iam.error.IamException;
import com.github.xingjianluo.springbootiamjava.iam.model.Credential;
import com.github.xingjianluo.springbootiamjava.tests.support.ManualClock;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 并发刷新测试：同一凭证并发刷新只能有一次成功，其余全部以可区分的
 * REFRESH_CONFLICT 失败；成功后旧凭证立即失效。
 */
class CredentialRefreshConcurrencyTest {

    private static final Logger log = LoggerFactory.getLogger(CredentialRefreshConcurrencyTest.class);

    private final ManualClock clock = new ManualClock(1_000_000L);
    private final InMemoryCredentialStore store = new InMemoryCredentialStore();
    private final InMemoryAuditService audit = new InMemoryAuditService();
    private final CredentialService credentialService =
            new CredentialServiceImpl(store, audit, clock);

    @Test
    void concurrentRefresh_onlyOneSucceeds_othersGetConflict() throws Exception {
        final int threads = 16;
        Credential issued = credentialService.issue("alice", List.of("reader"), 60_000L);
        log.info("input: subject=alice, initialVersion={}, secret={}, concurrentRefreshThreads={}",
                issued.version(), issued.secret(), threads);

        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        ConcurrentLinkedQueue<Credential> winners = new ConcurrentLinkedQueue<>();
        ConcurrentLinkedQueue<ErrorCode> failureCodes = new ConcurrentLinkedQueue<>();

        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    Credential c = credentialService.refresh(issued.secret());
                    winners.add(c);
                } catch (IamException e) {
                    failureCodes.add(e.errorCode());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertThat(done.await(10, TimeUnit.SECONDS)).isTrue();
        pool.shutdownNow();

        log.info("basis: successCount={}, failureCount={}, failureCodes={}",
                winners.size(), failureCodes.size(), failureCodes);

        assertThat(winners).hasSize(1);
        Credential winner = winners.iterator().next();
        assertThat(winner.version()).isEqualTo(1L);
        assertThat(winner.secret()).isNotEqualTo(issued.secret());
        assertThat(failureCodes).hasSize(threads - 1);
        assertThat(failureCodes).allMatch(c -> c == ErrorCode.REFRESH_CONFLICT);

        // 旧凭证立即失效：既不能访问认证，也不能再刷新（均可区分）。
        log.info("post-condition: old secret authenticate -> expect INVALID_CREDENTIAL");
        ErrorCode authError = null;
        try {
            credentialService.authenticate(issued.secret());
        } catch (IamException e) {
            authError = e.errorCode();
        }
        assertThat(authError).isEqualTo(ErrorCode.INVALID_CREDENTIAL);

        ErrorCode refreshError = null;
        try {
            credentialService.refresh(issued.secret());
        } catch (IamException e) {
            refreshError = e.errorCode();
        }
        assertThat(refreshError).isEqualTo(ErrorCode.REFRESH_CONFLICT);
    }

    @Test
    void sequentialRefresh_rotatesEachTime_andChainStaysConsistent() {
        Credential c0 = credentialService.issue("bob", List.of("reader"), 60_000L);
        List<String> secrets = new ArrayList<>();
        secrets.add(c0.secret());
        Credential current = c0;
        for (int v = 1; v <= 5; v++) {
            current = credentialService.refresh(current.secret());
            secrets.add(current.secret());
            assertThat(current.version()).isEqualTo(v);
        }
        log.info("input: sequential refresh chain subject=bob, secretsInChain={}", secrets);
        log.info("basis: finalVersion={}, every older secret must be invalid", current.version());
        for (int i = 0; i < secrets.size() - 1; i++) {
            final String oldSecret = secrets.get(i);
            ErrorCode code = null;
            try {
                credentialService.authenticate(oldSecret);
            } catch (IamException e) {
                code = e.errorCode();
            }
            assertThat(code).isEqualTo(ErrorCode.INVALID_CREDENTIAL);
        }
        assertThat(credentialService.authenticate(current.secret()).version()).isEqualTo(5L);
    }
}
