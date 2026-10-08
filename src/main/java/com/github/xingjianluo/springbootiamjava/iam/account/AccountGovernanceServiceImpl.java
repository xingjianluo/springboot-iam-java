package com.github.xingjianluo.springbootiamjava.iam.account;

import com.github.xingjianluo.springbootiamjava.iam.audit.AuditEvent;
import com.github.xingjianluo.springbootiamjava.iam.audit.AuditOutcome;
import com.github.xingjianluo.springbootiamjava.iam.audit.AuditService;
import com.github.xingjianluo.springbootiamjava.iam.credential.BatchRevokeOutcome;
import com.github.xingjianluo.springbootiamjava.iam.credential.CredentialStore;
import com.github.xingjianluo.springbootiamjava.iam.credential.RevocationPlan;
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
 *   <li>审计可核对：审计事件（{@code REVOKE_ALL}）完整记录锁内分类结果——本次吊销、操作前已吊销、
 *       操作前已过期三类，各自同时给出数量与凭证稳定 id 列表，与接口返回、会话查询一一对应；
 *       每条 REVOKE_ALL 事件带唯一 {@code operationId}，重复执行也能逐次区分。</li>
 *   <li>原子性：审计写入与状态变更在存储变更锁内串联——先写审计，审计失败则一个都不改，
 *       对外抛 {@code AUDIT_UNAVAILABLE}（503，可重试）；绝不留下“吊销一半”的中间态。</li>
 *   <li>确定性：与并发刷新/单点撤销共用同一把存储锁，操作返回后该账号不存在仍可用的凭证，
 *       也不存在“已吊销又被刷新续期”的窗口（刷新对 REVOKED 状态一律拒绝）。</li>
 *   <li>幂等：重复执行结果稳定；账号当前无有效凭证时审计中 revokedCount 恒为 0、revokedIds 为空，
 *       并抛可区分的 {@code NO_ACTIVE_CREDENTIALS}（404，可忽略而非重试）。</li>
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
            // 审计钩子在存储变更锁内、落变更前执行：写入的就是本次操作真实的锁内分类结果，
            // 三类数量与 id 与随后返回给调用方的结果严格一致。
            AuditEvent event = buildEvent(operationId, subject, AuditOutcome.ALLOW, "REVOKE_ALL",
                    classificationDetail(plan.toRevoke(), plan.alreadyRevoked(), plan.expired()));
            boolean ok = auditService.record(event);
            if (!ok) {
                log.error("revoke-all fail-closed: audit unavailable, subject={}, operationId={}, "
                        + "plannedRevoked={}, alreadyRevoked={}, expired={}",
                        subject, operationId, plan.toRevokeCount(),
                        plan.alreadyRevokedCount(), plan.expiredCount());
            }
            return ok;
        });

        if (!outcome.auditAccepted()) {
            // 系统侧一时不可用：与“没有有效凭证”明确区分，调用方应重试。只透出安全原因码。
            throw new IamException(ErrorCode.AUDIT_UNAVAILABLE);
        }
        if (outcome.revoked().isEmpty()) {
            // 没有有效凭证：本次一条都没吊销，审计中 revokedCount=0、revokedIds=[]，
            // 仅把识别出的“已吊销/已过期”两类（含 id）留痕，绝不凭空记成本次吊销了几条。
            AuditEvent noOpEvent = buildEvent(operationId, subject, AuditOutcome.DENIED_INVALID,
                    ErrorCode.NO_ACTIVE_CREDENTIALS.name(),
                    classificationDetail(List.of(), outcome.alreadyRevoked(), outcome.expired()));
            if (!auditService.record(noOpEvent)) {
                // 拒绝结论不依赖审计可用性：仍按“没什么可做”反馈，仅留警告日志。
                log.warn("revoke-all no-op audit trail not written (decision unchanged): "
                        + "subject={}, operationId={}", subject, operationId);
            }
            log.info("revoke-all no-op: subject={}, operationId={}, alreadyRevokedIds={}, expiredIds={}",
                    subject, operationId, idsOf(outcome.alreadyRevoked()), idsOf(outcome.expired()));
            throw new IamException(ErrorCode.NO_ACTIVE_CREDENTIALS);
        }

        List<String> revokedIds = idsOf(outcome.revoked());
        log.info("revoke-all done: subject={}, operationId={}, revokedIds={}, alreadyRevokedIds={}, expiredIds={}",
                subject, operationId, revokedIds,
                idsOf(outcome.alreadyRevoked()), idsOf(outcome.expired()));
        return new BatchRevocationResult(operationId, subject, revokedIds.size(),
                outcome.alreadyRevokedCount(), outcome.expiredCount(), revokedIds);
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
                                  AuditOutcome outcome, String reasonCode, String classification) {
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
                "operationId=" + operationId + "; " + classification,
                -1L);
    }

    /**
     * 拼出三类分类的可核对明细：每类都是“数量 + 稳定 id 列表”，字段名固定、可解析，
     * 与 {@link BatchRevocationResult} 的字段一一对应。
     */
    static String classificationDetail(List<Credential> revoked,
                                       List<Credential> alreadyRevoked,
                                       List<Credential> expired) {
        List<String> revokedIds = idsOf(revoked);
        List<String> alreadyRevokedIds = idsOf(alreadyRevoked);
        List<String> expiredIds = idsOf(expired);
        return "revokedCount=" + revokedIds.size()
                + "; revokedIds=" + revokedIds
                + "; alreadyRevokedCount=" + alreadyRevokedIds.size()
                + "; alreadyRevokedIds=" + alreadyRevokedIds
                + "; expiredCount=" + expiredIds.size()
                + "; expiredIds=" + expiredIds;
    }

    private static List<String> idsOf(List<Credential> credentials) {
        return credentials.stream().map(Credential::credentialId).toList();
    }
}
