package com.github.xingjianluo.springbootiamjava.credential;

/**
 * 凭证本地存储抽象。链内操作均要求持有 {@link CredentialChain#lock()}。
 */
public interface CredentialStore {

    CredentialChain createChain(String subject);

    CredentialChain findChain(String chainId);

    CredentialState findState(String token);

    /** 在链锁内调用，保证 token 与链版本的注册一致性。 */
    void registerVersion(CredentialChain chain, CredentialState state);

    CredentialChain lockChainOf(String token);

    void unlockChain(CredentialChain chain);

    int versionNumberOf(CredentialChain chain, String token);
}
