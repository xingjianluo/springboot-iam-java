package com.github.xingjianluo.springbootiamjava.iam.model;

import java.util.List;
import java.util.Map;

/**
 * 一次授权判定的输入：主体、角色、属性、资源、动作。
 */
public record AuthzRequest(
        String subject,
        List<String> roles,
        Map<String, String> subjectAttributes,
        String resource,
        String action
) {
}
