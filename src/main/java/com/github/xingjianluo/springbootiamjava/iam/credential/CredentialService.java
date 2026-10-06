package com.github.xingjianluo.springbootiamjava.iam.credential;

import com.github.xingjianluo.springbootiamjava.iam.model.Credential;
import java.util.List;

/** 凭证生命周期服务：签发、校验、刷新（轮换）、撤销。 */
public interface CredentialService {

    /** 为主体签发新凭证。 */
    Credential issue(String subject, List<String> roles, long ttlMillis);

    /** 按密文解析并校验凭证状态/有效期；任何失败都抛出可区分的 IamException。 */
    Credential authenticate(String secret);

    /**
     * 刷新凭证：原子轮换，旧密文立即失效。
     * 并发刷新仅一次成功，竞争方得到 REFRESH_CONFLICT。
     */
    Credential refresh(String secret);

    /** 按稳定 id 撤销；不存在抛 UNKNOWN_CREDENTIAL_ID。 */
    void revoke(String credentialId);

    /**
     * 账号级批量吊销：一次操作吊销该账号当前所有仍生效的凭证（含刷新派生的后代凭证）。
     *
     * <p>整体成功或整体失败：审计写不进去时不留任何中间状态，抛 {@code AUDIT_UNAVAILABLE}；
     * 该账号名下没有任何凭证时抛 {@code NO_ACTIVE_CREDENTIALS}（与系统侧不可用可区分）。
     * 可重复执行：再次执行时已被吊销/已过期的凭证被识别并计入结果，状态保持稳定。
     */
    BulkRevokeResult revokeAllForSubject(String subject);

    /** 查看账号当前登录情况：当前仍有效的会话列表、数量与处置代次。 */
    AccountSessionSummary sessionsOf(String subject);
}
