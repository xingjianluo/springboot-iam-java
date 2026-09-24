package com.github.xingjianluo.springbootiamjava.subject;

import java.util.Map;
import java.util.Set;

/**
 * 主体属性的不可变快照。每次角色/属性变更产生新版本，授权判定只基于单一版本快照。
 */
public record SubjectProfile(String subject, Set<String> roles, Map<String, String> attributes, long version) {
}
