package com.github.xingjianluo.springbootiamjava.authz;

import com.github.xingjianluo.springbootiamjava.subject.SubjectProfile;

import java.util.Map;

/**
 * 一次授权判定的输入：主体快照 + 资源/动作 + 资源属性 + 环境属性。
 */
public record AuthorizationRequest(
        SubjectProfile subject,
        String resource,
        String action,
        Map<String, String> resourceAttributes,
        Map<String, String> environment
) {
}
