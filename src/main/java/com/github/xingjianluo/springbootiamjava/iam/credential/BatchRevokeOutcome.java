package com.github.xingjianluo.springbootiamjava.iam.credential;

import com.github.xingjianluo.springbootiamjava.iam.model.Credential;
import java.util.List;

/**
 * 存储层批量吊销的结果，携带三类的完整分类（数量 + 可辨识 id），
 * 使接口返回与审计记录能逐条互相核对。
 *
 * @param revoked           本次实际被吊销的凭证（吊销后的视图，状态均为 REVOKED）
 * @param alreadyRevokedIds 操作前已处于 REVOKED 的凭证稳定 id（识别，不重复计入）
 * @param expiredIds        操作前已过期的凭证稳定 id（识别，不吊销也不计入）
 * @param auditAccepted     审计钩子是否接受；false 表示存储已回滚，本次操作整体未生效
 */
public record BatchRevokeOutcome(List<Credential> revoked,
                                 List<String> alreadyRevokedIds,
                                 List<String> expiredIds,
                                 boolean auditAccepted) {

    /** 操作前已吊销的数量（识别，不重复计入）。 */
    public int alreadyRevoked() {
        return alreadyRevokedIds.size();
    }

    /** 操作前已过期的数量（识别，不吊销也不计入）。 */
    public int expired() {
        return expiredIds.size();
    }

    public static BatchRevokeOutcome rolledBack() {
        return new BatchRevokeOutcome(List.of(), List.of(), List.of(), false);
    }
}
