package com.github.xingjianluo.springbootiamjava.iam.model;

/** 授权判定结论。 */
public enum DecisionReason {
    /** 显式允许。 */
    ALLOW,
    /** 显式拒绝（DENY 优先）。 */
    EXPLICIT_DENY,
    /** 无任何策略命中，按默认拒绝处理。 */
    NO_MATCHING_POLICY
}
