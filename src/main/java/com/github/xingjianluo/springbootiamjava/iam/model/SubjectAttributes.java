package com.github.xingjianluo.springbootiamjava.iam.model;

import java.util.Map;

/**
 * 主体属性的不可变快照。
 */
public record SubjectAttributes(String subject, Map<String, String> attributes, long revision) {
}
