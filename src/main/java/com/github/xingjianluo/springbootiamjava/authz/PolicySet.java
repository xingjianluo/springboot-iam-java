package com.github.xingjianluo.springbootiamjava.authz;

import java.util.List;

/**
 * 策略集合的不可变快照（version 单调递增）。
 */
public record PolicySet(long version, List<PolicyRule> rules) {
}
