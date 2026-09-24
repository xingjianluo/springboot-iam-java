package com.github.xingjianluo.springbootiamjava.audit;

/**
 * 审计事件：还原"输入 + 判定依据 + 结果"的完整链路。
 */
public record AuditEvent(
        long timestampMillis,
        String traceId,
        String action,
        String subject,
        String resource,
        String actionVerb,
        String credentialToken,
        String chainId,
        String result,
        String reason,
        String decisionBasis
) {
    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private long timestampMillis;
        private String traceId;
        private String action;
        private String subject;
        private String resource;
        private String actionVerb;
        private String credentialToken;
        private String chainId;
        private String result;
        private String reason;
        private String decisionBasis;

        public Builder timestampMillis(long v) { this.timestampMillis = v; return this; }
        public Builder traceId(String v) { this.traceId = v; return this; }
        public Builder action(String v) { this.action = v; return this; }
        public Builder subject(String v) { this.subject = v; return this; }
        public Builder resource(String v) { this.resource = v; return this; }
        public Builder actionVerb(String v) { this.actionVerb = v; return this; }
        public Builder credentialToken(String v) { this.credentialToken = v; return this; }
        public Builder chainId(String v) { this.chainId = v; return this; }
        public Builder result(String v) { this.result = v; return this; }
        public Builder reason(String v) { this.reason = v; return this; }
        public Builder decisionBasis(String v) { this.decisionBasis = v; return this; }

        public AuditEvent build() {
            return new AuditEvent(timestampMillis, traceId, action, subject, resource,
                    actionVerb, credentialToken, chainId, result, reason, decisionBasis);
        }
    }
}
