package com.github.xingjianluo.springbootiamjava.iam.account;

import com.github.xingjianluo.springbootiamjava.iam.audit.AuditEvent;
import com.github.xingjianluo.springbootiamjava.iam.audit.AuditOutcome;
import com.github.xingjianluo.springbootiamjava.iam.audit.AuditService;
import com.github.xingjianluo.springbootiamjava.iam.credential.BatchRevokeOutcome;
import com.github.xingjianluo.springbootiamjava.iam.credential.CredentialStore;
import com.github.xingjianluo.springbootiamjava.iam.credential.RevokePlan;
import com.github.xingjianluo.springbootiamjava.iam.credential.StoredCredential;
import com.github.xingjianluo.springbootiamjava.iam.error.ErrorCode;
import com.github.xingjianluo.springbootiamjava.iam.error.IamException;
import com.github.xingjianluo.springbootiamjava.iam.model.Credential;
import com.github.xingjianluo.springbootiamjava.iam.model.CredentialStatus;
import com.github.xingjianluo.springbootiamjava.iam.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 账号维度凭证治理实现。
 *
 * <p>批量吊销语义：
 * <ul>
 *   <li>原子性：审计写入与状态变更在存储变更锁内串联——先写审计，审计失败则一个都不改，
 *       对外抛 {@code AUDIT_UNAVAILABLE}（503，可重试）；绝不留下“吊销一半”的中间态。</li>
 *   <li>确定性：与并发刷新/单点撤销共用同一把存储锁，操作返回后该账号不存在仍可用的凭证，
 *       也不存在“已吊销又被刷新续期”的窗口（刷新对 REVOKED 状态一律拒绝）。</li>
 *   <li>幂等：重复执行结果稳定；账号当前无有效凭证时抛可区分的
 *       {@code NO_ACTIVE_CREDENTIALS}（404，可忽略而非重试）。</li>
 * </ul>
 * 会话汇总为只读快照，不取变更锁，不阻塞正常访问与刷新。
 */
@Service
public class AccountGovernanceServiceImpl implements AccountGovernanceService {

    private static final Logger log = LoggerFactory.getLogger(AccountGovernanceServiceImpl.class);

    private final CredentialStore store;
    private final AuditService auditService;
    private final Clock clock;

    public AccountGovernanceServiceImpl(CredentialStore store, AuditService auditService, Clock clock) {
        this.store = store;
        this.auditService = auditService;
        this.clock = clock;
    }

    @Override
    public BatchRevocationResult revokeAllForSubject(String subject) {
        if (subject == null || subject.isBlank()) {
            throw new IamException(ErrorCode.MALFORMED_REQUEST, "subject is required");
        }
        String operationId = "op_" + UUID.randomUUID();
        long now = clock.nowMillis();

        BatchRevokeOutcome outcome = store.revokeAllBySubject(subject, now, plan -> {
            // 审计钩子在存储变更锁内执行：写不进去则整体不落变更。
            // 审计内容直接取自存储层分类计划，三类数量与 id 和本次真实分类逐条一致。
            AuditEvent event = buildEvent(operationId, subject, AuditOutcome.ALLOW,
                    "REVOKE_ALL", detail(plan));
            boolean ok = auditService.record(event);
            if (!ok) {
                log.error("revoke-all fail-closed: audit unavailable, subject={}, operationId={}",
                        subject, operationId);
            }
            return ok;
        });

        if (!outcome.auditAccepted()) {
            // 系统侧一时不可用：与“没有有效凭证”明确区分，调用方应重试。
            throw new IamException(ErrorCode.AUDIT_UNAVAILABLE);
        }
        if (outcome.revoked().isEmpty()) {
            log.info("revoke-all no-op: subject={}, operationId={}, alreadyRevoked={}, expired={}",
                    subject, operationId, outcome.alreadyRevoked(), outcome.expired());
            // 尽力留痕（拒绝结论不依赖审计可用性）；同样带上三类的可辨识 id，便于对账。
            auditService.record(buildEvent(operationId, subject, AuditOutcome.DENIED_INVALID,
                    ErrorCode.NO_ACTIVE_CREDENTIALS.name(),
                    "no active credentials; revokedCount=0; revokedIds=[]"
                            + "; alreadyRevoked=" + outcome.alreadyRevoked()
                            + "; alreadyRevokedIds=" + outcome.alreadyRevokedIds()
                            + "; expired=" + outcome.expired()
                            + "; expiredIds=" + outcome.expiredIds()));
            throw new IamException(ErrorCode.NO_ACTIVE_CREDENTIALS);
        }

        List<String> revokedIds = outcome.revoked().stream().map(Credential::credentialId).toList();
        log.info("revoke-all done: subject={}, operationId={}, revoked={}, alreadyRevoked={}, expired={}, ids={}",
                subject, operationId, revokedIds.size(), outcome.alreadyRevoked(),
                outcome.expired(), revokedIds);
        return new BatchRevocationResult(operationId, subject, revokedIds.size(),
                outcome.alreadyRevoked(), outcome.expired(), revokedIds,
                outcome.alreadyRevokedIds(), outcome.expiredIds());
    }

    @Override
    public SessionSummary sessionsOf(String subject) {
        if (subject == null || subject.isBlank()) {
            throw new IamException(ErrorCode.MALFORMED_REQUEST, "subject is required");
        }
        long now = clock.nowMillis();
        List<SessionView> sessions = new ArrayList<>();
        for (StoredCredential stored : store.findBySubject(subject)) {
            Credential view = stored.view();
            if (view.status() == CredentialStatus.ACTIVE && now <= view.expiresAt()) {
                sessions.add(new SessionView(view.credentialId(), view.version(),
                        view.issuedAt(), view.expiresAt()));
            }
        }
        SessionSummary summary = new SessionSummary(subject, sessions.size(), List.copyOf(sessions));
        log.info("session summary: subject={}, activeCount={}, sessions={}",
                subject, summary.activeCount(), sessions);
        return summary;
    }

    private AuditEvent buildEvent(String operationId, String subject,
                                  AuditOutcome outcome, String reasonCode, String detail) {
        return new AuditEvent(
                "evt_" + UUID.randomUUID(),
                clock.nowMillis(),
                "REVOKE_ALL",
                null,
                subject,
                null,
                null,
                outcome,
                reasonCode,
                "operationId=" + operationId + "; " + detail,
                -1L);
    }

    /**
     * 批量吊销审计明细：三类各自的数量 + 稳定 id 列表，与接口返回一一对应，
     * 可与会话汇总（仍有效的 credentialId）互相核对处置是否收敛。
     */
    private static String detail(RevokePlan plan) {
        List<String> revokedIds = plan.toRevoke().stream().map(Credential::credentialId).toList();
        List<String> alreadyRevokedIds = plan.alreadyRevoked().stream()
                .map(Credential::credentialId).toList();
        List<String> expiredIds = plan.expired().stream()
                .map(Credential::credentialId).toList();
        return "revokedCount=" + revokedIds.size() + "; revokedIds=" + revokedIds
                + "; alreadyRevoked=" + alreadyRevokedIds.size()
                + "; alreadyRevokedIds=" + alreadyRevokedIds
                + "; expired=" + expiredIds.size()
                + "; expiredIds=" + expiredIds;
    }
}
