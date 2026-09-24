package com.github.xingjianluo.springbootiamjava.iam.model;

import java.util.List;
import java.util.Map;

/**
 * 某一修订号下的授权世界不可变快照：全部策略 + 主体属性。
 * 一次判定只基于一个快照，保证变更生效边界内结果一致收敛。
 */
public record AuthzSnapshot(long revision, List<Policy> policies, Map<String, SubjectAttributes> subjects) {
}
