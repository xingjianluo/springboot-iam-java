package com.github.xingjianluo.springbootiamjava.iam.credential;

import com.github.xingjianluo.springbootiamjava.iam.model.Credential;
import java.util.function.UnaryOperator;

/** 凭证存储：按凭证 id 与密文索引，支持原子插入、查询、轮换、撤销。 */
public interface CredentialStore {

    /** 插入新凭证；id 已存在时返回 false。 */
    boolean insert(Credential credential);

    /** 按稳定 id 查询；不存在返回 null。 */
    StoredCredential findById(String credentialId);

    /** 按密文反查持有点；不存在返回 null（旧密文轮换后立即查不到）。 */
    StoredCredential findBySecret(String secret);

    /**
     * 以密文定位凭证并原子轮换。密文索引更新与 CAS 在同一把存储锁内完成，
     * 保证旧密文失效与新密文生效是同一个原子动作。
     */
    RotateResult rotate(String secret, long nowMillis, UnaryOperator<Credential> generator);

    /** 按稳定 id 撤销；不存在返回 false。幂等。 */
    boolean revoke(String credentialId);

    /** 测试/本地验证支持：清空。 */
    void clear();
}
