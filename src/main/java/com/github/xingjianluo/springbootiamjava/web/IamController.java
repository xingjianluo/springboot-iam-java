package com.github.xingjianluo.springbootiamjava.web;

import com.github.xingjianluo.springbootiamjava.iam.access.AccessResult;
import com.github.xingjianluo.springbootiamjava.iam.account.AccountGovernanceService;
import com.github.xingjianluo.springbootiamjava.iam.account.BatchRevocationResult;
import com.github.xingjianluo.springbootiamjava.iam.account.SessionSummary;
import com.github.xingjianluo.springbootiamjava.iam.access.AccessService;
import com.github.xingjianluo.springbootiamjava.iam.audit.AuditEvent;
import com.github.xingjianluo.springbootiamjava.iam.audit.AuditService;
import com.github.xingjianluo.springbootiamjava.iam.authz.AuthzStore;
import com.github.xingjianluo.springbootiamjava.iam.credential.CredentialService;
import com.github.xingjianluo.springbootiamjava.iam.error.ErrorCode;
import com.github.xingjianluo.springbootiamjava.iam.error.IamException;
import com.github.xingjianluo.springbootiamjava.iam.model.Credential;
import com.github.xingjianluo.springbootiamjava.iam.model.Policy;
import com.github.xingjianluo.springbootiamjava.iam.model.PolicyEffect;
import com.github.xingjianluo.springbootiamjava.iam.model.SubjectAttributes;
import com.github.xingjianluo.springbootiamjava.web.dto.Dtos.AccessRequest;
import com.github.xingjianluo.springbootiamjava.web.dto.Dtos.BatchRevocationResponse;
import com.github.xingjianluo.springbootiamjava.web.dto.Dtos.AccessResponse;
import com.github.xingjianluo.springbootiamjava.web.dto.Dtos.CredentialView;
import com.github.xingjianluo.springbootiamjava.web.dto.Dtos.IssueRequest;
import com.github.xingjianluo.springbootiamjava.web.dto.Dtos.PolicyRequest;
import com.github.xingjianluo.springbootiamjava.web.dto.Dtos.SessionSummaryResponse;
import com.github.xingjianluo.springbootiamjava.web.dto.Dtos.SessionViewDto;
import com.github.xingjianluo.springbootiamjava.web.dto.Dtos.SubjectRequest;
import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/**
 * IAM 入口：凭证生命周期、受保护访问、策略/主体变更、审计查询与故障注入。
 */
@RestController
public class IamController {

    private static final long DEFAULT_TTL_MILLIS = 3600_000L;

    private final CredentialService credentialService;
    private final AccessService accessService;
    private final AuthzStore authzStore;
    private final AuditService auditService;
    private final AccountGovernanceService accountGovernanceService;

    public IamController(CredentialService credentialService,
                         AccessService accessService,
                         AuthzStore authzStore,
                         AuditService auditService,
                         AccountGovernanceService accountGovernanceService) {
        this.credentialService = credentialService;
        this.accessService = accessService;
        this.authzStore = authzStore;
        this.auditService = auditService;
        this.accountGovernanceService = accountGovernanceService;
    }

    @PostMapping("/iam/credentials")
    public CredentialView issue(@RequestBody IssueRequest request) {
        if (request == null) {
            throw new IamException(ErrorCode.MALFORMED_REQUEST);
        }
        long ttl = request.ttlMillis() == null ? DEFAULT_TTL_MILLIS : request.ttlMillis();
        return toView(credentialService.issue(request.subject(), request.roles(), ttl));
    }

    @PostMapping("/iam/credentials/refresh")
    public CredentialView refresh(
            @RequestHeader(name = "Authorization", required = false) String authorization) {
        return toView(credentialService.refresh(extractBearer(authorization)));
    }

    @PostMapping("/iam/credentials/{credentialId}/revoke")
    public Map<String, Object> revoke(@PathVariable String credentialId) {
        credentialService.revoke(credentialId);
        return Map.of("credentialId", credentialId, "status", "REVOKED");
    }

    @PostMapping("/iam/accounts/{subject}/revoke-all")
    public BatchRevocationResponse revokeAll(@PathVariable String subject) {
        BatchRevocationResult result = accountGovernanceService.revokeAllForSubject(subject);
        return new BatchRevocationResponse(result.operationId(), result.subject(),
                result.revokedCount(), result.alreadyRevokedCount(), result.expiredCount(),
                result.revokedCredentialIds(), result.alreadyRevokedCredentialIds(),
                result.expiredCredentialIds());
    }

    @GetMapping("/iam/accounts/{subject}/sessions")
    public SessionSummaryResponse sessions(@PathVariable String subject) {
        SessionSummary summary = accountGovernanceService.sessionsOf(subject);
        return new SessionSummaryResponse(summary.subject(), summary.activeCount(),
                summary.sessions().stream()
                        .map(v -> new SessionViewDto(v.credentialId(), v.version(),
                                v.issuedAt(), v.expiresAt()))
                        .toList());
    }

    @PostMapping("/iam/access")
    public AccessResponse access(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @RequestBody AccessRequest request) {
        if (request == null) {
            throw new IamException(ErrorCode.MALFORMED_REQUEST);
        }
        AccessResult result = accessService.access(
                extractBearer(authorization), request.resource(), request.action());
        String auditId = result.auditEvent() == null ? null : result.auditEvent().eventId();
        return new AccessResponse(result.allowed(), result.reasonCode(), result.subject(),
                result.resource(), result.action(), result.policyRevision(), auditId);
    }

    @PostMapping("/iam/policies")
    public Map<String, Object> upsertPolicy(@RequestBody PolicyRequest request) {
        if (request == null || request.policyId() == null || request.effect() == null) {
            throw new IamException(ErrorCode.MALFORMED_REQUEST,
                    "policyId and effect are required");
        }
        final PolicyEffect effect;
        try {
            effect = PolicyEffect.valueOf(request.effect().trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IamException(ErrorCode.MALFORMED_REQUEST, "effect must be ALLOW or DENY");
        }
        Map<String, String> attrs = request.attributeEquals() == null
                ? Map.of() : Map.copyOf(request.attributeEquals());
        Policy policy = new Policy(request.policyId(), effect, request.resourcePrefix(),
                request.action(),
                request.anyOfRoles() == null ? List.of() : List.copyOf(request.anyOfRoles()),
                attrs);
        authzStore.upsertPolicy(policy);
        return Map.of("policyId", policy.policyId(), "effect", effect.name());
    }

    @PostMapping("/iam/subjects")
    public Map<String, Object> upsertSubject(@RequestBody SubjectRequest request) {
        if (request == null || request.subject() == null) {
            throw new IamException(ErrorCode.MALFORMED_REQUEST, "subject is required");
        }
        long revision = authzStore.snapshot().revision();
        Map<String, String> attrs = request.attributes() == null
                ? Map.of() : Map.copyOf(request.attributes());
        authzStore.upsertSubject(new SubjectAttributes(request.subject(), attrs, revision + 1));
        return Map.of("subject", request.subject(), "attributes", attrs);
    }

    @GetMapping("/iam/audit")
    public List<AuditEvent> audit() {
        return auditService.findAll();
    }

    @PostMapping("/test/audit-writable/{writable}")
    public Map<String, Object> setAuditWritable(@PathVariable boolean writable) {
        auditService.setWritable(writable);
        return Map.of("auditWritable", writable);
    }

    @PostMapping("/test/authz-faulty/{faulty}")
    public Map<String, Object> setAuthzFaulty(@PathVariable boolean faulty) {
        authzStore.setFaulty(faulty);
        return Map.of("authzFaulty", faulty);
    }

    private static String extractBearer(String authorization) {
        if (authorization == null || authorization.isBlank()) {
            throw new IamException(ErrorCode.INVALID_CREDENTIAL);
        }
        String value = authorization.trim();
        if (value.regionMatches(true, 0, "Bearer ", 0, 7)) {
            value = value.substring(7).trim();
        }
        if (value.isBlank()) {
            throw new IamException(ErrorCode.INVALID_CREDENTIAL);
        }
        return value;
    }

    private static CredentialView toView(Credential c) {
        return new CredentialView(c.credentialId(), c.secret(), c.subject(), c.roles(),
                c.issuedAt(), c.expiresAt(), c.status().name(), c.version());
    }
}
