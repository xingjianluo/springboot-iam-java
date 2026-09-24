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
}
