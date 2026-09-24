package com.github.xingjianluo.springbootiamjava.iam.access;

import com.github.xingjianluo.springbootiamjava.iam.audit.AuditEvent;
import com.github.xingjianluo.springbootiamjava.iam.audit.AuditOutcome;
import com.github.xingjianluo.springbootiamjava.iam.audit.AuditService;
import com.github.xingjianluo.springbootiamjava.iam.authz.PolicyEvaluator;
import com.github.xingjianluo.springbootiamjava.iam.credential.CredentialService;
import com.github.xingjianluo.springbootiamjava.iam.credential.CredentialStore;
import com.github.xingjianluo.springbootiamjava.iam.credential.StoredCredential;
import com.github.xingjianluo.springbootiamjava.iam.error.ErrorCode;
import com.github.xingjianluo.springbootiamjava.iam.error.IamException;
import com.github.xingjianluo.springbootiamjava.iam.model.AuthzDecision;
import com.github.xingjianluo.springbootiamjava.iam.model.AuthzRequest;
import com.github.xingjianluo.springbootiamjava.iam.model.Credential;
import com.github.xingjianluo.springbootiamjava.iam.model.CredentialStatus;
import com.github.xingjianluo.springbootiamjava.iam.time.Clock;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 访问编排实现。
 *
 * <p>链路（每一步都产生可解释、可区分的结论）：
 * <pre>
 *   参数校验 -> 凭证认证(INVALID/EXPIRED/REVOKED) -> 授权判定(DENY/默认拒绝/INDETERMINATE)
 *             -> 放行前凭证复查(消除撤销/轮换竞态) -> 审计落盘(失败则拒绝放行)
 * </pre>
 * 拒绝路径先落审计再抛出携带安全错误码的 {@link IamException}，由全局异常处理器映射为
 * 401/403/500/503；仅放行时返回 {@link AccessResult}。
 * 失败关闭原则：无法判定（依赖异常）或审计不可写时，受保护操作一律不放行。
 */
@Service
public class AccessServiceImpl implements AccessService {

    private static final Logger log = LoggerFactory.getLogger(AccessServiceImpl.class);

    private final CredentialService credentialService;
    private final CredentialStore credentialStore;
    private final PolicyEvaluator policyEvaluator;
    private final AuditService auditService;
    private final Clock clock;

    public AccessServiceImpl(CredentialService credentialService,
                             CredentialStore credentialStore,
                             PolicyEvaluator policyEvaluator,
                             AuditService auditService,
                             Clock clock) {
        this.credentialService = credentialService;
        this.credentialStore = credentialStore;
        this.policyEvaluator = policyEvaluator;
        this.auditService = auditService;
        this.clock = clock;
    }

    @Override
    public AccessResult access(String secret, String resource, String action) {
        if (resource == null || resource.isBlank() || action == null || action.isBlank()) {
            throw new IamException(ErrorCode.MALFORMED_REQUEST, "resource and action are required");
        }

        // 1) 凭证认证：任何失败都映射为可区分原因，并落审计（拒绝不依赖审计可用性）。
        Credential credential;
        try {
            credential = credentialService.authenticate(secret);
        } catch (IamException e) {
            throw reject(e.errorCode(), mapCredentialFailure(e.errorCode()), null,
                    resource, action, null, 0L, "authentication failed: " + e.errorCode());
        }

        // 2) 授权判定（基于单个一致快照）。依赖异常 -> 失败关闭。
        AuthzDecision decision;
        try {
            decision = policyEvaluator.evaluate(new AuthzRequest(
                    credential.subject(), credential.roles(), null, resource, action));
        } catch (IamException e) {
            throw reject(e.errorCode(), AuditOutcome.ERROR_AUTHZ_INDETERMINATE,
                    credential, resource, action, null, 0L,
                    "authz dependency failure: " + e.errorCode());
        } catch (RuntimeException e) {
            throw reject(ErrorCode.AUTHZ_INDETERMINATE, AuditOutcome.ERROR_AUTHZ_INDETERMINATE,
                    credential, resource, action, null, 0L, "authz unexpected failure");
        }

        if (!decision.allow()) {
            throw reject(ErrorCode.POLICY_DENIED, AuditOutcome.DENIED_POLICY,
                    credential, resource, action, decision, decision.policyRevision(),
                    "decision=" + decision.reason() + ", matchedPolicies=" + decision.matchedPolicyIds()
                            + ", policyRevision=" + decision.policyRevision());
        }

        // 3) 放行前复查：消除“判定后、放行前”凭证被撤销/轮换/过期的竞态。
        //    按稳定 id 重新读取当前状态，确保已撤销凭证永远不可能被放行。
        StoredCredential live = credentialStore.findById(credential.credentialId());
        Credential latest = live == null ? null : live.view();
        if (latest == null || latest.status() == CredentialStatus.REVOKED) {
            throw reject(ErrorCode.CREDENTIAL_REVOKED, AuditOutcome.DENIED_REVOKED,
                    credential, resource, action, decision, decision.policyRevision(),
                    "credential revoked after authz decision; credentialVersionAtAuth="
                            + credential.version());
        }
        if (latest.version() != credential.version()
                || latest.status() != CredentialStatus.ACTIVE
                || clock.nowMillis() > latest.expiresAt()) {
            // 被并发轮换（旧凭证立即失效）或在间隙过期，一律按无效拒绝。
            throw reject(ErrorCode.INVALID_CREDENTIAL, AuditOutcome.DENIED_INVALID,
                    credential, resource, action, decision, decision.policyRevision(),
                    "credential changed/expired between decision and release; expectedVersion="
                            + credential.version() + ", liveVersion=" + latest.version()
                            + ", liveStatus=" + latest.status());
        }

        // 4) 审计落盘：受保护操作只有在审计成功写入后才允许放行（失败关闭）。
        AuditEvent event = buildEvent(credential, resource, action, AuditOutcome.ALLOW,
                "ALLOW",
                "ALLOW; matchedPolicies=" + decision.matchedPolicyIds()
                        + "; policyRevision=" + decision.policyRevision()
                        + "; credentialVersion=" + latest.version(),
                latest.version());
        log.info("access input: subject={}, resource={}, action={} | basis: ALLOW, policies={}, revision={}, credentialVersion={}",
                credential.subject(), resource, action, decision.matchedPolicyIds(),
                decision.policyRevision(), latest.version());
        if (!auditService.record(event)) {
            // 审计不可写：本应放行的请求必须失败关闭。此时审计本身不可写，记录通常也会失败，
            // 但结论绝不放行，并以可区分的 AUDIT_UNAVAILABLE 返回 503。
            AuditEvent failedEvent = buildEvent(credential, resource, action,
                    AuditOutcome.ERROR_AUDIT_UNAVAILABLE, ErrorCode.AUDIT_UNAVAILABLE.name(),
                    "audit write failed; request fail-closed; policyRevision="
                            + decision.policyRevision(), credential.version());
            auditService.record(failedEvent);
            log.error("access fail-closed: audit unavailable, subject={}, resource={}, action={}",
                    credential.subject(), resource, action);
            throw new IamException(ErrorCode.AUDIT_UNAVAILABLE);
        }
        return new AccessResult(true, "ALLOW", credential.subject(), resource, action,
                decision.policyRevision(), event);
    }

    /**
     * 统一拒绝出口：先尽力落审计（拒绝结论不依赖审计可用性），再抛出安全异常。
     */
    private IamException reject(ErrorCode code, AuditOutcome outcome,
                                Credential credential, String resource, String action,
                                AuthzDecision decision, long policyRevision, String detail) {
        long version = credential == null ? -1L : credential.version();
        AuditEvent event = buildEvent(credential, resource, action, outcome, code.name(),
                detail + (decision == null ? "" : ", decision=" + decision.reason()), version);
        auditService.record(event);
        log.warn("access denied: subject={}, resource={}, action={}, reason={}, basis={}",
                credential == null ? null : credential.subject(), resource, action, code, detail);
        return new IamException(code);
    }

    private AuditOutcome mapCredentialFailure(ErrorCode code) {
        return switch (code) {
            case CREDENTIAL_EXPIRED -> AuditOutcome.DENIED_EXPIRED;
            case CREDENTIAL_REVOKED -> AuditOutcome.DENIED_REVOKED;
            case REFRESH_CONFLICT -> AuditOutcome.DENIED_REFRESH_CONFLICT;
            default -> AuditOutcome.DENIED_INVALID;
        };
    }

    private AuditEvent buildEvent(Credential credential, String resource, String action,
                                  AuditOutcome outcome, String reasonCode,
                                  String detail, long credentialVersion) {
        return new AuditEvent(
                "evt_" + UUID.randomUUID(),
                clock.nowMillis(),
                "ACCESS",
                credential == null ? null : credential.credentialId(),
                credential == null ? null : credential.subject(),
                resource,
                action,
                outcome,
                reasonCode,
                detail,
                credentialVersion);
    }
}
