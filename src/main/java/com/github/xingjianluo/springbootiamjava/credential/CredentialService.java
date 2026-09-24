package com.github.xingjianluo.springbootiamjava.credential;

import com.github.xingjianluo.springbootiamjava.audit.AuditEvent;
import com.github.xingjianluo.springbootiamjava.audit.AuditService;
import com.github.xingjianluo.springbootiamjava.common.ApiException;
import com.github.xingjianluo.springbootiamjava.common.ErrorCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 凭证生命周期服务。
 *
 * <p>关键并发/失败语义：
 * <ul>
 *     <li>刷新即轮换：新凭证注册成功的同一临界区内旧凭证立即标记 ROTATED 失效；</li>
 *     <li>同一凭证的并发刷新由链锁串行：仅第一个看到旧凭证 ACTIVE 的请求成功，
 *         其余得到 {@link ErrorCode#REFRESH_CONFLICT}，与"非法凭证"(CREDENTIAL_INVALID) 可区分；</li>
 *     <li>撤销作用于整条链：撤销提交后，链上所有版本（含被轮换的旧凭证）一律失效；</li>
 *     <li>审计先于状态提交；刷新在审计不可写时轮换完全不提交，旧凭证保持 ACTIVE；</li>
 * </ul>
 */
@Service
public class CredentialService {

    public static final long DEFAULT_TTL_MILLIS = 30 * 60 * 1000L;

    private static final Logger log = LoggerFactory.getLogger(CredentialService.class);

    private final CredentialStore store;
    private final AuditService audit;

    public CredentialService(CredentialStore store, AuditService audit) {
        this.store = store;
        this.audit = audit;
    }

    public CredentialView issue(String subject, Long ttlMillis) {
        if (subject == null || subject.isBlank()) {
            throw new ApiException(ErrorCode.BAD_REQUEST, "subject must not be blank");
        }
        long ttl = ttlMillis == null ? DEFAULT_TTL_MILLIS : ttlMillis;
        if (ttl <= 0) {
            throw new ApiException(ErrorCode.BAD_REQUEST, "ttlMillis must be positive");
        }
        long now = System.currentTimeMillis();
        CredentialChain chain = store.createChain(subject);
        String token = Identifiers.newToken();
        CredentialState state = new CredentialState(token, chain.chainId(), subject, now, now + ttl);

        // 先审计，审计不可写则不产生任何可用凭证
        audit.append(AuditEvent.builder()
                .timestampMillis(now)
                .action("CREDENTIAL_ISSUE")
                .subject(subject)
                .credentialToken(token)
                .chainId(chain.chainId())
                .result("ISSUED")
                .reason("ttlMillis=" + ttl)
                .decisionBasis("statusBefore=NEW,ttlMillis=" + ttl)
                .build());

        synchronized (chain.lock()) {
            store.registerVersion(chain, state);
        }
        log.info("credential issued subject={} chain={} version=1", subject, chain.chainId());
        return CredentialView.from(state, 1);
    }

    public CredentialView refresh(String oldToken) {
        if (oldToken == null || oldToken.isBlank()) {
            throw new ApiException(ErrorCode.CREDENTIAL_MISSING, "credential is required");
        }
        CredentialChain chain = store.lockChainOf(oldToken);
        if (chain == null) {
            throw new ApiException(ErrorCode.CREDENTIAL_INVALID, "credential is invalid");
        }
        try {
            return doRefresh(oldToken, chain);
        } finally {
            store.unlockChain(chain);
        }
    }

    private CredentialView doRefresh(String oldToken, CredentialChain chain) {
        long now = System.currentTimeMillis();
        CredentialState old = store.findState(oldToken);
        int oldVersion = store.versionNumberOf(chain, oldToken);

        ValidationOutcome outcome = validateForRefresh(old, chain, now);
        if (outcome != ValidationOutcome.OK) {
            throw outcome.toException();
        }

        long ttl = old.expiresAtMillis() - old.issuedAtMillis();
        String newToken = Identifiers.newToken();
        CredentialState next = new CredentialState(
                newToken, chain.chainId(), chain.subject(), now, now + ttl);

        // 审计作为提交门禁：此时尚未发生任何状态变更，审计失败直接中止，
        // 旧凭证保持 ACTIVE、新版本永不注册（轮换完全不提交）
        try {
            audit.append(AuditEvent.builder()
                    .timestampMillis(now)
                    .action("CREDENTIAL_REFRESH")
                    .subject(chain.subject())
                    .credentialToken(newToken)
                    .chainId(chain.chainId())
                    .result("ROTATED")
                    .reason("rotatedFromVersion=" + oldVersion)
                    .decisionBasis("oldToken=" + oldToken
                            + ",oldVersion=" + oldVersion
                            + ",oldStatusBefore=ACTIVE,newVersion=" + (oldVersion + 1))
                    .build());
        } catch (RuntimeException auditFailure) {
            log.warn("refresh aborted before commit due to audit failure, old credential remains active chain={}",
                    chain.chainId());
            throw auditFailure;
        }

        // 同一临界区内：注册新版本 + 旧版本立即失效
        store.registerVersion(chain, next);
        old.markRotated(newToken, now);
        log.info("credential rotated subject={} chain={} v{}->v{}",
                chain.subject(), chain.chainId(), oldVersion, oldVersion + 1);
        return CredentialView.from(next, oldVersion + 1);
    }

    public CredentialView revoke(String token, String reason) {
        if (token == null || token.isBlank()) {
            throw new ApiException(ErrorCode.CREDENTIAL_MISSING, "credential is required");
        }
        CredentialChain chain = store.lockChainOf(token);
        if (chain == null) {
            throw new ApiException(ErrorCode.CREDENTIAL_INVALID, "credential is invalid");
        }
        try {
            return doRevoke(token, reason, chain);
        } finally {
            store.unlockChain(chain);
        }
    }

    private CredentialView doRevoke(String token, String reason, CredentialChain chain) {
        long now = System.currentTimeMillis();
        CredentialState state = store.findState(token);
        int version = store.versionNumberOf(chain, token);
        String safeReason = reason == null || reason.isBlank() ? "USER_REVOKED" : reason;

        // 撤销是受保护操作：审计先于状态提交。审计失败时保持原状并拒绝，状态不确定也绝不放行
        audit.append(AuditEvent.builder()
                .timestampMillis(now)
                .action("CREDENTIAL_REVOKE")
                .subject(chain.subject())
                .credentialToken(token)
                .chainId(chain.chainId())
                .result(chain.chainRevoked() ? "ALREADY_REVOKED" : "REVOKED")
                .reason(safeReason)
                .decisionBasis("chainRevokedBefore=" + chain.chainRevoked()
                        + ",version=" + version)
                .build());

        chain.markChainRevoked(now, safeReason);
        int versions = chain.versionTokens().size();
        for (String versionToken : chain.versionTokens()) {
            CredentialState s = store.findState(versionToken);
            if (s != null && s.status() == CredentialStatus.ACTIVE) {
                s.markRevoked(now, safeReason);
            }
        }
        log.info("credential chain revoked subject={} chain={} versions={} reason={}",
                chain.subject(), chain.chainId(), versions, safeReason);
        return CredentialView.from(state, version < 0 ? versions : version);
    }

    /**
     * 在持有链锁的前提下校验刷新输入。
     */
    private ValidationOutcome validateForRefresh(CredentialState state, CredentialChain chain, long now) {
        if (state == null) {
            return ValidationOutcome.INVALID;
        }
        if (chain.chainRevoked()) {
            return ValidationOutcome.REVOKED;
        }
        if (state.status() == CredentialStatus.REVOKED) {
            // 已被轮换或撤销：并发刷新的后来者得到可区分的冲突原因
            return state.replacedByToken() != null
                    ? ValidationOutcome.ROTATED
                    : ValidationOutcome.REVOKED;
        }
        if (state.status() == CredentialStatus.EXPIRED || now >= state.expiresAtMillis()) {
            state.markExpired();
            return ValidationOutcome.EXPIRED;
        }
        return ValidationOutcome.OK;
    }

    private enum ValidationOutcome {
        OK, INVALID, EXPIRED, REVOKED, ROTATED;

        ApiException toException() {
            if (this == OK) {
                throw new IllegalStateException("OK is not an error");
            }
            return switch (this) {
                case INVALID -> new ApiException(ErrorCode.CREDENTIAL_INVALID, "credential is invalid");
                case EXPIRED -> new ApiException(ErrorCode.CREDENTIAL_EXPIRED, "credential has expired");
                case REVOKED -> new ApiException(ErrorCode.CREDENTIAL_REVOKED, "credential has been revoked");
                case ROTATED -> new ApiException(ErrorCode.REFRESH_CONFLICT,
                        "credential has already been rotated by a concurrent refresh");
                case OK -> throw new IllegalStateException("unreachable");
            };
        }
    }
}
