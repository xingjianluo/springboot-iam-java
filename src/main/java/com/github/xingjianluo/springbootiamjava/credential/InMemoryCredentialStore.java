package com.github.xingjianluo.springbootiamjava.credential;

import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * 基于 ConcurrentHashMap 的本地凭证存储。
 *
 * <p>并发模型：token -> chain 的映射先查后锁，链内所有变更（签发新版本、轮换、撤销、
 * 校验在途请求）都在同一把 {@link CredentialChain#lock()} 下完成，因此：
 * <ul>
 *     <li>同一凭证并发刷新：链锁串行化，只有第一个请求能看到 ACTIVE 的旧凭证并轮换成功；</li>
 *     <li>撤销与在途请求交错：二者抢同一把锁，撤销提交后任何在途校验都必然看到 REVOKED。</li>
 * </ul>
 */
@Component
public class InMemoryCredentialStore implements CredentialStore {

    private final ConcurrentMap<String, CredentialChain> chains = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, CredentialState> tokens = new ConcurrentHashMap<>();

    @Override
    public CredentialChain createChain(String subject) {
        CredentialChain chain = new CredentialChain(Identifiers.newChainId(), subject);
        chains.put(chain.chainId(), chain);
        return chain;
    }

    @Override
    public CredentialChain findChain(String chainId) {
        return chainId == null ? null : chains.get(chainId);
    }

    @Override
    public CredentialState findState(String token) {
        return token == null ? null : tokens.get(token);
    }

    @Override
    public void registerVersion(CredentialChain chain, CredentialState state) {
        tokens.put(state.token(), state);
        chain.versionTokens().add(state.token());
    }

    @Override
    public CredentialChain lockChainOf(String token) {
        CredentialState state = tokens.get(token);
        if (state == null) {
            return null;
        }
        CredentialChain chain = chains.get(state.chainId());
        if (chain == null) {
            return null;
        }
        chain.lock().lock();
        return chain;
    }

    @Override
    public void unlockChain(CredentialChain chain) {
        if (chain != null) {
            chain.lock().unlock();
        }
    }

    @Override
    public int versionNumberOf(CredentialChain chain, String token) {
        int index = chain.versionTokens().indexOf(token);
        return index < 0 ? -1 : index + 1;
    }

    /** 测试隔离：清空全部本地凭证。 */
    public void clear() {
        chains.clear();
        tokens.clear();
    }
}
