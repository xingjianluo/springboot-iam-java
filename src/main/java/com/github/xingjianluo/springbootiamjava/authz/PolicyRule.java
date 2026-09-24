package com.github.xingjianluo.springbootiamjava.authz;

import java.util.Map;

/**
 * 一条策略规则：可按主体、资源、动作、角色以及主体/资源属性匹配（RBAC + ABAC）。
 * name 唯一；显式 DENY 规则在引擎中优先于 ALLOW。
 */
public record PolicyRule(
        String name,
        Effect effect,
        String subject,
        String resource,
        String action,
        java.util.Set<String> anyRole,
        Map<String, String> subjectAttributes,
        Map<String, String> resourceAttributes,
        int priority
) {
}
