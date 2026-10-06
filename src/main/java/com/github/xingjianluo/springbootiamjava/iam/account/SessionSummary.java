package com.github.xingjianluo.springbootiamjava.iam.account;

import java.util.List;

/**
 * 账号当前登录情况汇总：仅统计“现在还生效”的凭证/会话。
 *
 * @param subject       账号主体
 * @param activeCount   当前有效会话数（等于 sessions 的大小，冗余给出便于直接统计）
 * @param sessions      每个有效会话的可辨识视图（credentialId + version）
 */
public record SessionSummary(String subject, int activeCount, List<SessionView> sessions) {
}
