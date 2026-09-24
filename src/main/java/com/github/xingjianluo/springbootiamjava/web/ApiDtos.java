package com.github.xingjianluo.springbootiamjava.web;

import java.util.Map;
import java.util.Set;

/** 本地验证用 HTTP 出入参。 */
public final class ApiDtos {

    private ApiDtos() {
    }

    public record IssueRequest(String subject, Long ttlMillis) {
    }

    public record RefreshRequest(String token) {
    }

    public record RevokeRequest(String token, String reason) {
    }

    public record AccessRequest(String token, String resource, String action,
                                Map<String, String> resourceAttributes,
                                Map<String, String> environment) {
    }

    public record SubjectUpsertRequest(String subject, Set<String> roles,
                                       Map<String, String> attributes) {
    }

    public record Message(String message) {
    }
}
