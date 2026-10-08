package com.github.xingjianluo.springbootiamjava.iam.credential;

import com.github.xingjianluo.springbootiamjava.iam.model.Credential;
import java.util.List;

/**
 * 存储层批量吊销的结果。
 *
 * <p>三类分类各自同时给出数量与凭证稳定 id，保证调用方写审计时既能记数量也能记具体凭证，
 * 与接口返回、账号会话查询互相核对：
 * <ul>
 *   <li>{@code revoked*}：本次实际被吊销的凭证（吊销后视图，状态均为 REVOKED）；</li>
 *   <li>{@code alreadyRevoked*}：操作前已处于 REVOKED 的凭证（识别，不重复计入）；</li>
 *   <li>{@code expired*}：操作前已过期的凭证（识别，不吊销也不计入）。</li>
 * </ul>
 *
 * @param revoked           本次实际被吊销的凭证（吊销后的视图，状态均为 REVOKED）
 * @param alreadyRevoked    操作前已处于 REVOKED 的凭证视图
 * @param expired           操作前已过期的凭证视图
 * @param auditAccepted     审计钩子是否接受；false 表示存储已回滚，本次操作整体未生效
 */
public record BatchRevokeOutcome(List<Credential> revoked,
                                 List<Credential> alreadyRevoked,
                                 List<Credential> expired,
                                 boolean auditAccepted) {

    public BatchRevokeOutcome {
        revoked = List.copyOf(revoked);
        alreadyRevoked = List.copyOf(alreadyRevoked);
        expired = List.copyOf(expired);
    }

    public int revokedCount() {
        return revoked.size();
    }

    public int alreadyRevokedCount() {
        return alreadyRevoked.size();
    }

    public int expiredCount() {
        return expired.size();
    }

    /** 审计钩子拒绝：一条都不改，分类计数也不外泄（整体未生效）。 */
    public static BatchRevokeOutcome rolledBack() {
        return new BatchRevokeOutcome(List.of(), List.of(), List.of(), false);
    }
}
