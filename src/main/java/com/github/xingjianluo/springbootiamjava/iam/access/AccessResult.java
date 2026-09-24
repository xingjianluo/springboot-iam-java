package com.github.xingjianluo.springbootiamjava.iam.access;

import com.github.xingjianluo.springbootiamjava.iam.audit.AuditEvent;

/**
 * 受保护访问放行时的产物（拒绝时访问链路直接抛出携带错误码的异常）。
 */
public record AccessResult(
        boolean allowed,
        String reasonCode,
        String subject,
        String resource,
        String action,
        long policyRevision,
        AuditEvent auditEvent
) {
}
