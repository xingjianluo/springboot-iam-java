package com.github.xingjianluo.springbootiamjava.iam.audit;

/** 审计记录的最终处置结论（对外可区分失败类型的关键依据）。 */
public enum AuditOutcome {
    ALLOW,
    DENIED_INVALID,
    DENIED_EXPIRED,
    DENIED_REVOKED,
    DENIED_POLICY,
    DENIED_REFRESH_CONFLICT,
    ERROR_AUTHZ_INDETERMINATE,
    ERROR_AUDIT_UNAVAILABLE,
    ERROR_INTERNAL
}
