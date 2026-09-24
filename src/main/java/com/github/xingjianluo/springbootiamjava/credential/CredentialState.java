package com.github.xingjianluo.springbootiamjava.credential;

/**
 * 单个凭证版本的本地可变状态。
 */
public class CredentialState {

    private final String token;
    private final String chainId;
    private final String subject;
    private final long issuedAtMillis;
    private final long expiresAtMillis;
    private volatile CredentialStatus status;
    private volatile String replacedByToken;
    private volatile long revokedAtMillis;
    private volatile String revokeReason;

    public CredentialState(String token, String chainId, String subject,
                           long issuedAtMillis, long expiresAtMillis) {
        this.token = token;
        this.chainId = chainId;
        this.subject = subject;
        this.issuedAtMillis = issuedAtMillis;
        this.expiresAtMillis = expiresAtMillis;
        this.status = CredentialStatus.ACTIVE;
    }

    public String token() { return token; }
    public String chainId() { return chainId; }
    public String subject() { return subject; }
    public long issuedAtMillis() { return issuedAtMillis; }
    public long expiresAtMillis() { return expiresAtMillis; }
    public CredentialStatus status() { return status; }
    public String replacedByToken() { return replacedByToken; }
    public long revokedAtMillis() { return revokedAtMillis; }
    public String revokeReason() { return revokeReason; }

    public void markRotated(String newToken, long atMillis) {
        this.status = CredentialStatus.REVOKED;
        this.replacedByToken = newToken;
        this.revokedAtMillis = atMillis;
        this.revokeReason = "ROTATED";
    }

    public void markRevoked(long atMillis, String reason) {
        this.status = CredentialStatus.REVOKED;
        this.revokedAtMillis = atMillis;
        this.revokeReason = reason;
    }

    public void markExpired() {
        this.status = CredentialStatus.EXPIRED;
    }
}
