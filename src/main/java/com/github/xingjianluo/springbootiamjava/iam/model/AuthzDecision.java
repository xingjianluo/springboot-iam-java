package com.github.xingjianluo.springbootiamjava.iam.model;

import java.util.List;

/**
 * 授权判定结果：是否允许、原因、命中的策略 id 列表、判定所依据的策略修订号。
 * 该对象是审计“判定依据”的一部分。
 */
public record AuthzDecision(
        boolean allow,
        DecisionReason reason,
        List<String> matchedPolicyIds,
        long policyRevision
) {
}
