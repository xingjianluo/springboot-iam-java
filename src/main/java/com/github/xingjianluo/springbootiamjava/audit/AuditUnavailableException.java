package com.github.xingjianluo.springbootiamjava.audit;

/**
 * 审计不可写。不向外部透出底层细节，由全局处理器映射为 AUDIT_UNAVAILABLE。
 */
public class AuditUnavailableException extends RuntimeException {
    public AuditUnavailableException(String internalReason) {
        super(internalReason);
    }
}
