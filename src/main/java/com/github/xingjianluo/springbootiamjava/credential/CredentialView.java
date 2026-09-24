package com.github.xingjianluo.springbootiamjava.credential;

/**
 * 对外可见的凭证信息（不含内部锁等）。
 */
public record CredentialView(
        String token,
        String chainId,
        String subject,
        long issuedAtMillis,
        long expiresAtMillis,
        int version,
        CredentialStatus status,
        String replacedByToken,
        String revokeReason
) {
    public static CredentialView from(CredentialState state, int version) {
        return new CredentialView(
                state.token(),
                state.chainId(),
                state.subject(),
                state.issuedAtMillis(),
                state.expiresAtMillis(),
                version,
                state.status(),
                state.replacedByToken(),
                state.revokeReason());
    }
}
