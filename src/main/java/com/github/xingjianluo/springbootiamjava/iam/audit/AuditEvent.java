package com.github.xingjianluo.springbootiamjava.iam.audit;

import java.util.List;

/**
 * 不可变审计事件，完整还原一次判定的输入与依据。
 *
 * @param eventId         事件唯一 id
 * @param timestampMillis 事件时间
 * @param operation       操作类型（ISSUE / REFRESH / REVOKE / ACCESS）
 * @param credentialId    凭证稳定 id（可空）
 * @param subject         主体（可空）
 * @param resource        访问资源（可空）
 * @param action          访问动作（可空）
 * @param outcome         处置结论
 * @param reasonCode      可区分的原因码
 * @param decisionDetail  判定依据文本（命中策略 id、策略修订号、凭证版本等）
 * @param credentialVersion 判定时凭证版本
 */
public record AuditEvent(
        String eventId,
        long timestampMillis,
        String operation,
        String credentialId,
        String subject,
        String resource,
        String action,
        AuditOutcome outcome,
        String reasonCode,
        String decisionDetail,
        long credentialVersion
) {
    public static List<String> csvHeader() {
        return List.of("eventId", "timestampMillis", "operation", "credentialId", "subject",
                "resource", "action", "outcome", "reasonCode", "decisionDetail", "credentialVersion");
    }
}
