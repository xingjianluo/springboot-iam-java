package com.github.xingjianluo.springbootiamjava.iam.credential;

import java.util.List;

/**
 * 账号当前登录情况汇总（不可变快照）。
 *
 * <p>只统计“当前还有效”的凭证（ACTIVE 且未过期）；历史累积的已吊销/已过期凭证不列入，
 * 因此账号历史凭证很多时该查询的开销与结果大小都只与活跃会话数相关。
 *
 * @param subject         账号
 * @param activeCount     当前有效凭证/会话数（等于 sessions 的大小，冗余给出便于快速确认收敛）
 * @param sessions        当前有效会话明细（按 credentialId 排序，确定输出）
 * @param revocationEpoch 该账号当前的处置代次：与批量吊销返回的代次比对即可确认处置是否已收敛
 * @param asOfMillis      汇总生成时刻（epoch 毫秒）
 */
public record AccountSessionSummary(
        String subject,
        int activeCount,
        List<SessionEntry> sessions,
        long revocationEpoch,
        long asOfMillis
) {

    /**
     * 单个有效会话的可辨识标识。
     *
     * @param credentialId 凭证稳定 id（轮换链不变）
     * @param issuedAt     当前代签发时间
     * @param expiresAt    当前代过期时间
     * @param version      当前凭证版本
     */
    public record SessionEntry(String credentialId, long issuedAt, long expiresAt, long version) {
    }

    public AccountSessionSummary {
        sessions = sessions == null ? List.of() : List.copyOf(sessions);
    }
}
