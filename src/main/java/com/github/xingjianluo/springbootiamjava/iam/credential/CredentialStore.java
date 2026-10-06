package com.github.xingjianluo.springbootiamjava.iam.credential;

import com.github.xingjianluo.springbootiamjava.iam.model.Credential;
import java.util.function.Function;
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

    /**
     * 账号级批量吊销：把该账号当前所有仍生效的凭证一次性吊销。
     *
     * <p>“归类 → 审计回调 → 应用吊销 + 代次递增”在同一个存储变更锁内完成：
     * <ul>
     *   <li>审计回调返回 false 时不做任何状态变更（整体失败，无中间态）；</li>
     *   <li>与并发刷新/撤销串行化：操作返回后该账号不存在仍生效的凭证，
     *       已吊销凭证也不可能被一次在途刷新重新续出有效凭证；</li>
     *   <li>轮换派生的后代凭证与祖先共用一个 credentialId（同一条凭证链），
     *       按 id 吊销天然覆盖整条链。</li>
     * </ul>
     *
     * @param subject       目标账号
     * @param nowMillis     当前时间，用于在锁内完成过期归类
     * @param auditCallback 在锁内、应用吊销之前调用；入参为即将应用的吊销计划（含新代次），
     *                      返回 true 才提交状态变更
     */
    BulkRevokeResult revokeAllBySubject(String subject, long nowMillis,
                                        Function<BulkRevokeResult, Boolean> auditCallback);

    /**
     * 账号当前登录情况汇总：只读操作，不持有存储变更锁，不阻塞正常访问与刷新。
     */
    AccountSessionSummary summarizeSubject(String subject, long nowMillis);

    /** 测试/本地验证支持：清空。 */
    void clear();
}
