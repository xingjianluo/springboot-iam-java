package com.github.xingjianluo.springbootiamjava.iam.credential;

import com.github.xingjianluo.springbootiamjava.iam.model.Credential;
import com.github.xingjianluo.springbootiamjava.iam.model.CredentialStatus;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.UnaryOperator;
import org.springframework.stereotype.Repository;

/**
 * 并发安全的内存凭证存储。
 *
 * <p>{@code byId} 与 {@code bySecret} 双索引，另有 {@code bySubject} 主体索引支撑账号级
 * 查询与批量吊销（主体 -> 该主体全部凭证 id，只增不删，数据规模上去后按主体定位仍是 O(该主体凭证数)）。
 * 所有变更（插入、轮换、撤销、批量吊销）都在同一把存储锁内串行完成，保证
 * “旧密文摘除 + CAS 轮换 + 新密文挂载”以及“批量吊销”各自是一个原子动作，
 * 任何并发请求都不可能观察到中间态，也不可能凭旧密文继续通过。
 *
 * <p>按主体的只读查询不取变更锁，不会长时间卡住正常访问与刷新。
 */
@Repository
public class InMemoryCredentialStore implements CredentialStore {

    private final Object mutationLock = new Object();
    private final ConcurrentHashMap<String, StoredCredential> byId = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> bySecret = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Set<String>> bySubject = new ConcurrentHashMap<>();

    @Override
    public boolean insert(Credential credential) {
        synchronized (mutationLock) {
            if (byId.containsKey(credential.credentialId())) {
                return false;
            }
            byId.put(credential.credentialId(), new StoredCredential(credential));
            bySecret.put(credential.secret(), credential.credentialId());
            bySubject.computeIfAbsent(credential.subject(), k -> ConcurrentHashMap.newKeySet())
                    .add(credential.credentialId());
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
    public List<StoredCredential> findBySubject(String subject) {
        if (subject == null) {
            return List.of();
        }
        Set<String> ids = bySubject.get(subject);
        if (ids == null || ids.isEmpty()) {
            return List.of();
        }
        // 只读快照：逐个按 id 取持有点，不取变更锁；持有点自身有内置锁保证视图一致。
        List<StoredCredential> result = new ArrayList<>(ids.size());
        for (String id : ids) {
            StoredCredential stored = byId.get(id);
            if (stored != null) {
                result.add(stored);
            }
        }
        return List.copyOf(result);
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
    public BatchRevokeOutcome revokeAllBySubject(String subject, long nowMillis,
                                                 Function<RevocationPlan, Boolean> auditHook) {
        synchronized (mutationLock) {
            // 与 rotate/revoke 同一把锁：批量吊销与并发刷新、并发单点撤销串行，
            // 返回之后该主体不可能再有凭证被放行或被刷新续期。
            List<StoredCredential> toRevoke = new ArrayList<>();
            List<Credential> toRevokeViews = new ArrayList<>();
            List<Credential> alreadyRevokedViews = new ArrayList<>();
            List<Credential> expiredViews = new ArrayList<>();
            for (StoredCredential stored : findBySubject(subject)) {
                Credential view = stored.view();
                if (view.status() == CredentialStatus.REVOKED) {
                    // 操作前已吊销：识别出具体是哪几条，不重复计入本次吊销。
                    alreadyRevokedViews.add(view);
                } else if (nowMillis > view.expiresAt()) {
                    // 已过期：识别出具体是哪几条，不计入吊销，避免误报。
                    expiredViews.add(view);
                } else {
                    toRevoke.add(stored);
                    toRevokeViews.add(view);
                }
            }
            RevocationPlan plan = new RevocationPlan(
                    toRevokeViews, alreadyRevokedViews, expiredViews);
            if (toRevoke.isEmpty()) {
                // 没有有效凭证：无需变更也无需审计钩子，整体无变更；
                // 仍把另两类的识别结果（含 id）带回，供上层写“无操作”审计与可区分反馈。
                return new BatchRevokeOutcome(List.of(),
                        plan.alreadyRevoked(), plan.expired(), true);
            }
            // 先审计后变更：审计钩子拿到锁内完整分类快照；钩子拒绝则一个都不改，
            // 绝不留下“吊销一半”的中间态。
            if (auditHook != null && !Boolean.TRUE.equals(auditHook.apply(plan))) {
                return BatchRevokeOutcome.rolledBack();
            }
            List<Credential> revokedViews = new ArrayList<>(toRevoke.size());
            for (StoredCredential stored : toRevoke) {
                stored.revoke();
                revokedViews.add(stored.view());
            }
            return new BatchRevokeOutcome(List.copyOf(revokedViews),
                    plan.alreadyRevoked(), plan.expired(), true);
        }
    }

    @Override
    public void clear() {
        synchronized (mutationLock) {
            byId.clear();
            bySecret.clear();
            bySubject.clear();
        }
    }
}
