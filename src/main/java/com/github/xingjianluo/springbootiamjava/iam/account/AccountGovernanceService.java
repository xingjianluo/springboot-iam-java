package com.github.xingjianluo.springbootiamjava.iam.account;

/**
 * 账号维度的凭证治理：一键结束某账号全部登录、查看账号当前登录情况。
 */
public interface AccountGovernanceService {

    /**
     * 吊销该账号当前全部仍生效的凭证（含刷新派生的后代凭证，因轮换共用稳定 id 而一并终止）。
     * 整体成功或整体失败；可重复执行，结果稳定。
     *
     * @throws com.github.xingjianluo.springbootiamjava.iam.error.IamException
     *         NO_ACTIVE_CREDENTIALS：该账号当前没有有效凭证；AUDIT_UNAVAILABLE：审计不可写，整体失败
     */
    BatchRevocationResult revokeAllForSubject(String subject);

    /** 查看该账号当前仍生效的凭证/会话汇总。 */
    SessionSummary sessionsOf(String subject);
}
