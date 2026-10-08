package com.github.xingjianluo.springbootiamjava.web.dto;

import java.util.List;
import java.util.Map;

/**
 * Web 层请求/响应 DTO 集合。全部为不可变记录，缺失字段为 null，
 * 由控制器负责参数校验并抛出 MALFORMED_REQUEST。
 */
public final class Dtos {

    private Dtos() {
    }

    public record IssueRequest(String subject, List<String> roles, Long ttlMillis) {
    }

    public record CredentialView(String credentialId, String secret, String subject,
                                 List<String> roles, long issuedAt, long expiresAt,
                                 String status, long version) {
    }

    public record AccessRequest(String resource, String action) {
    }

    public record AccessResponse(boolean allowed, String reason, String subject,
                                 String resource, String action, long policyRevision,
                                 String auditEventId) {
    }

    public record PolicyRequest(String policyId, String effect, String resourcePrefix,
                                String action, List<String> anyOfRoles,
                                Map<String, String> attributeEquals) {
    }

    public record SubjectRequest(String subject, Map<String, String> attributes) {
    }

    public record ErrorResponse(String error, String message) {
    }

    public record BatchRevocationResponse(String operationId, String subject, int revokedCount,
                                          int alreadyRevokedCount, int expiredCount,
                                          List<String> revokedCredentialIds,
                                          List<String> alreadyRevokedCredentialIds,
                                          List<String> expiredCredentialIds) {
    }

    public record SessionViewDto(String credentialId, long version, long issuedAt, long expiresAt) {
    }

    public record SessionSummaryResponse(String subject, int activeCount,
                                         List<SessionViewDto> sessions) {
    }
}
