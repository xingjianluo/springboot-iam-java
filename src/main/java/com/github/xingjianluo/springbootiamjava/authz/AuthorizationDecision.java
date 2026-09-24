package com.github.xingjianluo.springbootiamjava.authz;

/**
 * 判定结果：allow 为最终结论；basis 记录命中的规则与版本，供审计还原。
 *
 * <p>失败语义：策略匹配到 DENY 时 reason=DENY_RULE；没有任何规则匹配时 reason=DEFAULT_DENY；
 * 评估过程中依赖异常或输入不完整时 reason=INDETERMINATE。三种结果对外可区分，
 * 且后两者同样按拒绝处理（fail-closed）。
 */
public record AuthorizationDecision(
        boolean allow,
        Effect effect,
        String matchedRule,
        long policyVersion,
        long subjectVersion,
        String reason,
        String basis
) {
    public static final String REASON_DENY_RULE = "DENY_RULE";
    public static final String REASON_DEFAULT_DENY = "DEFAULT_DENY";
    public static final String REASON_INDETERMINATE = "INDETERMINATE";
}
