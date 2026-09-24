package com.github.xingjianluo.springbootiamjava.iam.credential;

import com.github.xingjianluo.springbootiamjava.iam.model.Credential;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.UnaryOperator;
import org.springframework.stereotype.Repository;

/**
 * 并发安全的内存凭证存储。
 *
 * <p>{@code byId} 与 {@code bySecret} 双索引；所有变更（插入、轮换、撤销）都在
 * 同一把存储锁内串行完成，保证“旧密文摘除 + CAS 轮换 + 新密文挂载”是一个原子动作，
 * 任何并发请求都不可能观察到中间态，也不可能凭旧密文继续通过。
 */
@Repository
public class InMemoryCredentialStore implements CredentialStore {

    private final Object mutationLock = new Object();
    private final ConcurrentHashMap<String, StoredCredential> byId = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> bySecret = new ConcurrentHashMap<>();

    @Override
    public boolean insert(Credential credential) {
        synchronized (mutationLock) {
            if (byId.containsKey(credential.credentialId())) {
                return false;
            }
            byId.put(credential.credentialId(), new StoredCredential(credential));
            bySecret.put(credential.secret(), credential.credentialId());
            return true;
        }
    }

    @Override
    public StoredCredential findById(String credentialId) {
        return byId.get(credentialId);
    }

    @Override
    public StoredCredential findBySecret(String secret) {
        if (secret == null) {
            return null;
        }
        String id = bySecret.get(secret);
        return id == null ? null : byId.get(id);
    }

    @Override
    public RotateResult rotate(String secret, long nowMillis, UnaryOperator<Credential> generator) {
        synchronized (mutationLock) {
            String id = secret == null ? null : bySecret.get(secret);
            StoredCredential stored = id == null ? null : byId.get(id);
            if (stored == null) {
                return RotateResult.of(RotateResult.Status.INVALID);
            }
            long expectedVersion = stored.view().version();
            RotateResult result = stored.compareAndRotate(expectedVersion, nowMillis, generator);
            if (result.status() == RotateResult.Status.SUCCESS) {
                // 原子切换索引：旧密文立即不可解析，新密文立即可用。
                bySecret.remove(secret);
                bySecret.put(result.credential().secret(), result.credential().credentialId());
            }
            return result;
        }
    }

    @Override
    public boolean revoke(String credentialId) {
        synchronized (mutationLock) {
            StoredCredential stored = byId.get(credentialId);
            if (stored == null) {
                return false;
            }
            // 撤销是终态：保留密文 -> id 映射，使后续出示该密文能被判定为“已撤销”，
            // 与“无效（已轮换）”区分开；状态检查保证已撤销凭证绝不可能被放行。
            return stored.revoke();
        }
    }

    @Override
    public void clear() {
        synchronized (mutationLock) {
            byId.clear();
            bySecret.clear();
        }
    }
}
