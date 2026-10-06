package com.github.xingjianluo.springbootiamjava.iam.credential;

import com.github.xingjianluo.springbootiamjava.iam.audit.AuditEvent;
import com.github.xingjianluo.springbootiamjava.iam.audit.AuditOutcome;
import com.github.xingjianluo.springbootiamjava.iam.audit.AuditService;
import com.github.xingjianluo.springbootiamjava.iam.error.ErrorCode;
import com.github.xingjianluo.springbootiamjava.iam.error.IamException;
import com.github.xingjianluo.springbootiamjava.iam.model.Credential;
import com.github.xingjianluo.springbootiamjava.iam.model.CredentialStatus;
import com.github.xingjianluo.springbootiamjava.iam.time.Clock;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import java.util.function.UnaryOperator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 凭证生命周期服务实现。
 *
 * <p>失败原因可区分：INVALID / EXPIRED / REVOKED / REFRESH_CONFLICT / UNKNOWN_CREDENTIAL_ID。
 * 校验优先级：存在性 &gt; 撤销 &gt; 过期 &gt; 状态有效（被轮换的旧凭证因密文索引摘除直接表现为无效）。
 * 生命周期操作均尽力留痕；其审计失败不改变操作本身语义（受保护“访问”的失败关闭在 AccessService 中保证）。
 */
@Service
public class CredentialServiceImpl implements CredentialService {

    private static final Logger log = LoggerFactory.getLogger(CredentialServiceImpl.class);

    private final CredentialStore store;
    private final AuditService auditService;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();

    public CredentialServiceImpl(CredentialStore store, AuditService auditService, Clock clock) {
        this.store = store;
        this.auditService = auditService;
        this.clock = clock;
    }

    @Override
    public Credential issue(String subject, List<String> roles, long ttlMillis) {
        if (subject == null || subject.isBlank()) {
            throw new IamException(ErrorCode.MALFORMED_REQUEST, "subject is required");
        }
        if (ttlMillis <= 0) {
            throw new IamException(ErrorCode.MALFORMED_REQUEST, "ttlMillis must be positive");
        }
        long now = clock.nowMillis();
        List<String> roleSnapshot = roles == null ? List.of() : List.copyOf(roles);
        Credential credential = new Credential(
                "cred_" + randomToken(12),
                "tok_" + randomToken(24),
                subject,
                roleSnapshot,
                now,
                now + ttlMillis,
                CredentialStatus.ACTIVE,
                0L);
        if (!store.insert(credential)) {
            throw new IamException(ErrorCode.INTERNAL_ERROR);
        }
        log.info("credential issued: subject={}, credentialId={}, roles={}, ttlMillis={}",
                subject, credential.credentialId(), roleSnapshot, ttlMillis);
        audit(credential, "ISSUE", AuditOutcome.ALLOW, "ISSUED",
                "issued; roles=" + roleSnapshot + "; ttlMillis=" + ttlMillis);
        return credential;
    }

    @Override
    public Credential authenticate(String secret) {
        StoredCredential stored = store.findBySecret(secret);
        if (stored == null) {
            throw new IamException(ErrorCode.INVALID_CREDENTIAL);
        }
        Credential c = stored.view();
        // 撤销优先判定：撤销与在途请求交错时，撤销一旦完成，后续请求立即被拒。
        if (c.status() == CredentialStatus.REVOKED) {
            throw new IamException(ErrorCode.CREDENTIAL_REVOKED);
        }
        if (clock.nowMillis() > c.expiresAt()) {
            throw new IamException(ErrorCode.CREDENTIAL_EXPIRED);
        }
        if (c.status() != CredentialStatus.ACTIVE) {
            throw new IamException(ErrorCode.INVALID_CREDENTIAL);
        }
        return c;
    }

    @Override
    public Credential refresh(String secret) {
        UnaryOperator<Credential> generator = current -> new Credential(
                current.credentialId(),
                "tok_" + randomToken(24),
                current.subject(),
                current.roles(),
                clock.nowMillis(),
                clock.nowMillis() + (current.expiresAt() - current.issuedAt()),
                CredentialStatus.ACTIVE,
                current.version() + 1);
        RotateResult result = store.rotate(secret, clock.nowMillis(), generator);
        switch (result.status()) {
            case SUCCESS:
                Credential c = result.credential();
                log.info("credential rotated: subject={}, credentialId={}, newVersion={}",
                        c.subject(), c.credentialId(), c.version());
                audit(c, "REFRESH", AuditOutcome.ALLOW, "ROTATED",
                        "rotated; newVersion=" + c.version());
                return c;
            case REVOKED:
                throw new IamException(ErrorCode.CREDENTIAL_REVOKED);
            case EXPIRED:
                throw new IamException(ErrorCode.CREDENTIAL_EXPIRED);
            case CONFLICT, INVALID:
                // 并发刷新仅一次成功，竞争方得到可区分的 REFRESH_CONFLICT。
                log.warn("refresh rejected: concurrent rotation or invalid secret");
                throw new IamException(ErrorCode.REFRESH_CONFLICT);
            default:
                throw new IamException(ErrorCode.INTERNAL_ERROR);
        }
    }

    @Override
    public void revoke(String credentialId) {
        StoredCredential stored = store.findById(credentialId);
        if (stored == null) {
            throw new IamException(ErrorCode.UNKNOWN_CREDENTIAL_ID);
        }
        boolean changed = store.revoke(credentialId);
        Credential view = stored.view();
        log.info("credential revoked: credentialId={}, changed={}", credentialId, changed);
        audit(view, "REVOKE", AuditOutcome.ALLOW, "REVOKED",
                "revoked; stateChanged=" + changed + "; credentialVersion=" + view.version());
    }

    @Override
    public BulkRevokeResult revokeAllForSubject(String subject) {
        if (subject == null || subject.isBlank()) {
            throw new IamException(ErrorCode.MALFORMED_REQUEST, "subject is required");
        }
        BulkRevokeResult result = store.revokeAllBySubject(subject, clock.nowMillis(),
                plan -> auditService.record(buildBulkRevokeEvent(plan)));
        switch (result.status()) {
            case SUCCESS:
                log.info("bulk revoke committed: subject={}, revoked={}, alreadyRevoked={}, expired={}, epoch={}",
                        subject, result.revokedCredentialIds(), result.alreadyRevokedCredentialIds(),
                        result.expiredCredentialIds(), result.revocationEpoch());
                return result;
            case NO_CREDENTIALS:
                log.info("bulk revoke rejected: subject={} has no credentials", subject);
                throw new IamException(ErrorCode.NO_ACTIVE_CREDENTIALS);
            case AUDIT_FAILED:
                // 审计不可写：整体失败，存储层未做任何状态变更，调用方可安全重试。
                log.error("bulk revoke fail-closed: audit unavailable, subject={}", subject);
                throw new IamException(ErrorCode.AUDIT_UNAVAILABLE);
            default:
                throw new IamException(ErrorCode.INTERNAL_ERROR);
        }
    }

    @Override
    public AccountSessionSummary sessionsOf(String subject) {
        if (subject == null || subject.isBlank()) {
            throw new IamException(ErrorCode.MALFORMED_REQUEST, "subject is required");
        }
        AccountSessionSummary summary = store.summarizeSubject(subject, clock.nowMillis());
        log.info("session summary: subject={}, activeCount={}, epoch={}",
                subject, summary.activeCount(), summary.revocationEpoch());
        return summary;
    }

    private AuditEvent buildBulkRevokeEvent(BulkRevokeResult plan) {
        return new AuditEvent(
                "evt_" + UUID.randomUUID(),
                clock.nowMillis(),
                "REVOKE_ALL",
                null,
                plan.subject(),
                null,
                null,
                AuditOutcome.ALLOW,
                "REVOKE_ALL",
                "revoked=" + plan.revokedCredentialIds()
                        + "; alreadyRevoked=" + plan.alreadyRevokedCredentialIds()
                        + "; expired=" + plan.expiredCredentialIds()
                        + "; revocationEpoch=" + plan.revocationEpoch(),
                -1L);
    }

    private void audit(Credential c, String operation, AuditOutcome outcome,
                       String reasonCode, String detail) {
        AuditEvent event = new AuditEvent(
                "evt_" + UUID.randomUUID(),
                clock.nowMillis(),
                operation,
                c.credentialId(),
                c.subject(),
                null,
                null,
                outcome,
                reasonCode,
                detail,
                c.version());
        auditService.record(event);
    }

    private String randomToken(int byteLength) {
        byte[] bytes = new byte[byteLength];
        random.nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }
}
