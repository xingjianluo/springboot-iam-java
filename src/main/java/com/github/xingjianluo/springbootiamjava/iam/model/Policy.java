package com.github.xingjianluo.springbootiamjava.iam.model;

import java.util.Map;

/**
 * 基于角色或属性的授权策略（不可变值对象）。
 * 命中条件：资源前缀匹配 + 动作匹配 + 主体含任一所需角色（为空则不约束角色）
 *           + 属性等值条件全部满足（为空则不约束属性）。
 */
public record Policy(
        String policyId,
        PolicyEffect effect,
        String resourcePrefix,
        String action,
        java.util.List<String> anyOfRoles,
        Map<String, String> attributeEquals
) {
}
