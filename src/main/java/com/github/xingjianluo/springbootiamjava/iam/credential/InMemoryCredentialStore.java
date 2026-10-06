package com.github.xingjianluo.springbootiamjava.iam.credential;

import com.github.xingjianluo.springbootiamjava.iam.model.Credential;
import com.github.xingjianluo.springbootiamjava.iam.model.CredentialStatus;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.UnaryOperator;
import org.springframework.stereotype.Repository;

/**
 * 并发安全的内存凭证存储。
 *
 * <p>{@code byId} 与 {@code bySecret} 双索引；所有变更（插入、轮换、撤销）都在
 * 同一把存储锁内串行完成，保证“旧密文摘除 + CAS 轮换 + 新密文挂载”是一个原子动作，
 * 任何并发请求都不可能观察到中间态，也不可能凭旧密文继续通过。
 *
 * <p>账号维度额外维护 {@code bySubject}（账号 -> 其全部凭证 id）与
 * {@code revocationEpochs}（账号 -> 处置代次）两个索引，使批量吊销与会话汇总的
 * 开销只与该账号名下的凭证数相关，而非全库规模；二者均由同一把变更锁保护，
 * 与凭证状态变更保持同一串行化点。
 */
@Repository
public class InMemoryCredentialStore implements CredentialStore {

    private final Object mutationLock = new Object();
    private final ConcurrentHashMap<String, StoredCredential> byId = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> bySecret = new ConcurrentHashMap<>();
    /** 账号 -> 名下全部凭证 id（含历史已吊销/已过期），仅在 mutationLock 内读写。 */
    private final Map<String, Set<String>> bySubject = new HashMap<>();
    /** 账号 -> 已成功执行的批量吊销次数（处置代次），仅在 mutationLock 内读写。 */
    private final Map<String, Long> revocationEpochs = new HashMap<>();

    @Override
    public boolean insert(Credential credential) {
        synchronized (mutationLock) {
            if (byId.containsKey(credential.credentialId())) {
                return false;
            }
            byId.put(credential.credentialId(), new StoredCredential(credential));
            bySecret.put(credential.secret(), credential.credentialId());
            bySubject.computeIfAbsent(credential.subject(), k -> new LinkedHashSet<>())
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
    public BulkRevokeResult revokeAllBySubject(String subject, long nowMillis,
                                               Function<BulkRevokeResult, Boolean> auditCallback) {
        synchronized (mutationLock) {
            Set<String> ids = bySubject.get(subject);
            if (ids == null || ids.isEmpty()) {
                return BulkRevokeResult.of(BulkRevokeResult.Status.NO_CREDENTIALS, subject);
            }
            // 锁内归类：仍生效 -> 待吊销；已吊销 / 已过期 -> 显式识别，不算漏网或误报。
            List<String> toRevoke = new ArrayList<>();
            List<String> alreadyRevoked = new ArrayList<>();
            List<String> expired = new ArrayList<>();
            for (String id : ids) {
                StoredCredential stored = byId.get(id);
                if (stored == null) {
                    continue;
                }
                Credential view = stored.view();
                if (view.status() == CredentialStatus.REVOKED) {
                    alreadyRevoked.add(id);
                } else if (nowMillis > view.expiresAt()) {
                    expired.add(id);
                } else {
                    toRevoke.add(id);
                }
            }
            long nextEpoch = revocationEpochs.getOrDefault(subject, 0L) + 1;
            BulkRevokeResult plan = BulkRevokeResult.success(
                    subject, toRevoke, alreadyRevoked, expired, nextEpoch);
            // 审计先行：写不进去则整体失败，不做任何状态变更（无中间态）。
            if (auditCallback != null && !Boolean.TRUE.equals(auditCallback.apply(plan))) {
                return BulkRevokeResult.of(BulkRevokeResult.Status.AUDIT_FAILED, subject);
            }
            // 应用吊销：与并发刷新/撤销在同一把锁内串行，返回后该账号无生效凭证。
            for (String id : toRevoke) {
                StoredCredential stored = byId.get(id);
                if (stored != null) {
                    stored.revoke();
                }
            }
            revocationEpochs.put(subject, nextEpoch);
            return plan;
        }
    }

    @Override
    public AccountSessionSummary summarizeSubject(String subject, long nowMillis) {
        final List<String> ids;
        final long epoch;
        synchronized (mutationLock) {
            // 仅在锁内拷贝 id 集合与代次，随后锁外读取各凭证视图：
            // 汇总开销与账号活跃规模相关，且基本不占用变更锁，不阻塞访问与刷新。
            Set<String> owned = bySubject.get(subject);
            ids = owned == null ? List.of() : List.copyOf(owned);
            epoch = revocationEpochs.getOrDefault(subject, 0L);
        }
        List<AccountSessionSummary.SessionEntry> sessions = new ArrayList<>();
        for (String id : ids) {
            StoredCredential stored = byId.get(id);
            if (stored == null) {
                continue;
            }
            Credential view = stored.view();
            if (view.status() == CredentialStatus.ACTIVE && nowMillis <= view.expiresAt()) {
                sessions.add(new AccountSessionSummary.SessionEntry(
                        view.credentialId(), view.issuedAt(), view.expiresAt(), view.version()));
            }
        }
        sessions.sort(Comparator.comparing(AccountSessionSummary.SessionEntry::credentialId));
        return new AccountSessionSummary(subject, sessions.size(), sessions, epoch, nowMillis);
    }

    @Override
    public void clear() {
        synchronized (mutationLock) {
            byId.clear();
            bySecret.clear();
            bySubject.clear();
            revocationEpochs.clear();
        }
    }
}
