package com.github.xingjianluo.springbootiamjava.guard;

import com.github.xingjianluo.springbootiamjava.audit.AuditEvent;
import com.github.xingjianluo.springbootiamjava.audit.AuditService;
import com.github.xingjianluo.springbootiamjava.authz.AuthorizationDecision;
import com.github.xingjianluo.springbootiamjava.authz.AuthorizationRequest;
import com.github.xingjianluo.springbootiamjava.authz.PolicyEngine;
import com.github.xingjianluo.springbootiamjava.common.ApiException;
import com.github.xingjianluo.springbootiamjava.common.ErrorCode;
import com.github.xingjianluo.springbootiamjava.credential.CredentialChain;
import com.github.xingjianluo.springbootiamjava.credential.CredentialState;
import com.github.xingjianluo.springbootiamjava.credential.CredentialStatus;
import com.github.xingjianluo.springbootiamjava.credential.CredentialStore;
import com.github.xingjianluo.springbootiamjava.subject.SubjectDirectory;
import com.github.xingjianluo.springbootiamjava.subject.SubjectProfile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * 受保护资源的统一入口判定。
 *
 * <p>判定顺序（凭证 -> 主体快照 -> 策略快照 -> 授权 -> 审计 -> 放行）：
 * <ol>
 *     <li>对目标凭证所在链加锁后再校验凭证状态，与刷新/撤销互斥；因此撤销一旦提交，
 *         任何在途请求要么先于撤销完成、要么看到 REVOKED 被拒，不存在"撤销后仍可访问"；</li>
 *     <li>主体画像与策略各取一次不可变快照，单次判定内一致收敛，变更只在边界后生效；</li>
 *     <li>显式 DENY 优先；无法判定（INDETERMINATE）按拒绝处理；</li>
 *     <li>放行前必须完成审计写入，审计不可写则拒绝（{@link ErrorCode#AUDIT_UNAVAILABLE}）。</li>
 * </ol>
 */
@Component
public class AccessGuard {

    private static final Logger log = LoggerFactory.getLogger(AccessGuard.class);

    private final CredentialStore credentialStore;
    private final SubjectDirectory subjectDirectory;
    private final PolicyEngine policyEngine;
    private final AuditService auditService;

    public AccessGuard(CredentialStore credentialStore,
                       SubjectDirectory subjectDirectory,
                       PolicyEngine policyEngine,
                       AuditService auditService) {
        this.credentialStore = credentialStore;
        this.subjectDirectory = subjectDirectory;
        this.policyEngine = policyEngine;
        this.auditService = auditService;
    }

    public GuardResult authorizeAccess(String token, String resource, String action,
                                       Map<String, String> resourceAttributes,
                                       Map<String, String> environment) {
        long now = System.currentTimeMillis();
        if (token == null || token.isBlank()) {
            throw new ApiException(ErrorCode.CREDENTIAL_MISSING, "credential is required");
        }
        if (resource == null || resource.isBlank() || action == null || action.isBlank()) {
            throw new ApiException(ErrorCode.BAD_REQUEST, "resource and action are required");
        }

        // 与刷新/撤销抢同一把链锁；找不到 token 不持锁
        CredentialChain chain = credentialStore.lockChainOf(token);
        boolean locked = chain != null;
        try {
            if (chain == null) {
                throw new ApiException(ErrorCode.CREDENTIAL_INVALID, "credential is invalid");
            }
            CredentialState state = credentialStore.findState(token);
            if (state == null) {
                throw new ApiException(ErrorCode.CREDENTIAL_INVALID, "credential is invalid");
            }

            // 凭证状态校验全部在链锁内完成
            if (chain.chainRevoked() || state.status() == CredentialStatus.REVOKED) {
                String reason = chain.chainRevoked() ? chain.revokeReason() : state.revokeReason();
                denyAudit(now, "RESOURCE_ACCESS", state.subject(), resource, action, token,
                        chain.chainId(), "REJECTED", ErrorCode.CREDENTIAL_REVOKED.code(),
                        "credential revoked, reason=" + reason);
                throw new ApiException(ErrorCode.CREDENTIAL_REVOKED, "credential has been revoked");
            }
            if (state.status() == CredentialStatus.EXPIRED || now >= state.expiresAtMillis()) {
                state.markExpired();
                denyAudit(now, "RESOURCE_ACCESS", state.subject(), resource, action, token,
                        chain.chainId(), "REJECTED", ErrorCode.CREDENTIAL_EXPIRED.code(),
                        "credential expired at " + state.expiresAtMillis());
                throw new ApiException(ErrorCode.CREDENTIAL_EXPIRED, "credential has expired");
            }

            String subject = state.subject();
            String chainId = chain.chainId();

            // 取一次主体快照与一次策略快照，后续判定不再读目录/仓库
            SubjectProfile subjectSnapshot = subjectDirectory.snapshot(subject);
            AuthorizationDecision decision = policyEngine.evaluate(new AuthorizationRequest(
                    subjectSnapshot, resource, action,
                    resourceAttributes == null ? Map.of() : resourceAttributes,
                    environment == null ? Map.of() : environment));

            if (!decision.allow()) {
                ErrorCode code = AuthorizationDecision.REASON_INDETERMINATE.equals(decision.reason())
                        ? ErrorCode.AUTHZ_INDETERMINATE
                        : ErrorCode.AUTHZ_DENIED;
                denyAudit(now, "RESOURCE_ACCESS", subject, resource, action, token, chainId,
                        "REJECTED", code.code(), decision.basis());
                throw new ApiException(code, "access is denied by policy");
            }

            // 放行门禁：审计不可写绝不放行（异常向上传播，映射为 AUDIT_UNAVAILABLE）
            auditService.append(AuditEvent.builder()
                    .timestampMillis(now)
                    .action("RESOURCE_ACCESS")
                    .subject(subject)
                    .resource(resource)
                    .actionVerb(action)
                    .credentialToken(token)
                    .chainId(chainId)
                    .result("ALLOWED")
                    .reason(decision.matchedRule())
                    .decisionBasis(decision.basis())
                    .build());

            log.info("access allowed subject={} resource={} action={} basis={}",
                    subject, resource, action, decision.basis());
            return new GuardResult(subject, resource, action, decision.basis());
        } finally {
            if (locked) {
                credentialStore.unlockChain(chain);
            }
        }
    }

    private void denyAudit(long now, String actionName, String subject, String resource, String verb,
                           String token, String chainId, String result, String reason, String basis) {
        try {
            auditService.append(AuditEvent.builder()
                    .timestampMillis(now)
                    .action(actionName)
                    .subject(subject)
                    .resource(resource)
                    .actionVerb(verb)
                    .credentialToken(token)
                    .chainId(chainId)
                    .result(result)
                    .reason(reason)
                    .decisionBasis(basis)
                    .build());
        } catch (RuntimeException ex) {
            // 拒绝路径上审计失败同样 fail-closed：转换为审计错误，避免静默
            log.warn("deny-path audit append failed subject={} resource={} error={}",
                    subject, resource, ex.toString());
            throw ex;
        }
    }

    public record GuardResult(String subject, String resource, String action, String decisionBasis) {
    }
}
