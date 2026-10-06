package com.github.xingjianluo.springbootiamjava.iam.credential;

import com.github.xingjianluo.springbootiamjava.iam.model.Credential;
import java.util.List;

/**
 * 存储层批量吊销的结果。
 *
 * @param revoked         本次实际被吊销的凭证（吊销后的视图，状态均为 REVOKED）
 * @param alreadyRevoked  操作前已处于 REVOKED 的数量（识别，不重复计入）
 * @param expired         操作前已过期的数量（识别，不吊销也不计入）
 * @param auditAccepted   审计钩子是否接受；false 表示存储已回滚，本次操作整体未生效
 */
public record BatchRevokeOutcome(List<Credential> revoked, int alreadyRevoked,
                                 int expired, boolean auditAccepted) {

    public static BatchRevokeOutcome rolledBack() {
        return new BatchRevokeOutcome(List.of(), 0, 0, false);
    }
}
