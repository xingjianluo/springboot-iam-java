package com.github.xingjianluo.springbootiamjava.iam.credential;

import com.github.xingjianluo.springbootiamjava.iam.model.Credential;
import java.util.List;
import java.util.function.Function;
import java.util.function.UnaryOperator;

/** 凭证存储：按凭证 id 与密文索引，支持原子插入、查询、轮换、撤销与账号级批量吊销。 */
public interface CredentialStore {

    /** 插入新凭证；id 已存在时返回 false。 */
    boolean insert(Credential credential);

    /** 按稳定 id 查询；不存在返回 null。 */
    StoredCredential findById(String credentialId);

    /** 按密文反查持有点；不存在返回 null（旧密文轮换后立即查不到）。 */
    StoredCredential findBySecret(String secret);

    /**
     * 按主体查询其全部凭证持有点（含已吊销/已过期，用于识别与统计）。
     * 读路径不取变更锁，不阻塞正常访问与刷新。
     */
    List<StoredCredential> findBySubject(String subject);

    /**
     * 以密文定位凭证并原子轮换。密文索引更新与 CAS 在同一把存储锁内完成，
     * 保证旧密文失效与新密文生效是同一个原子动作。
     */
    RotateResult rotate(String secret, long nowMillis, UnaryOperator<Credential> generator);

    /** 按稳定 id 撤销；不存在返回 false。幂等。 */
    boolean revoke(String credentialId);

    /**
     * 账号级批量吊销：在同一把变更锁内先对待吊销清单执行审计钩子，
     * 钩子接受（返回 true）才落变更；钩子拒绝则一个都不改（整体失败，无中间态）。
     * 与并发 rotate/revoke 由同一把锁串行，返回后该主体不存在仍可用的凭证。
     *
     * @param subject    账号主体
     * @param nowMillis  当前时间，用于锁内过期判定
     * @param auditHook  入参为本次将吊销的凭证当前视图；返回 false 表示审计不可用
     */
    BatchRevokeOutcome revokeAllBySubject(String subject, long nowMillis,
                                          Function<List<Credential>, Boolean> auditHook);

    /** 测试/本地验证支持：清空。 */
    void clear();
}
