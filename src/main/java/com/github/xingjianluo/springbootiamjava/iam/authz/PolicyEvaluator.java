package com.github.xingjianluo.springbootiamjava.iam.authz;

import com.github.xingjianluo.springbootiamjava.iam.model.AuthzDecision;
import com.github.xingjianluo.springbootiamjava.iam.model.AuthzRequest;

/**
 * 策略判定器：在单个一致快照上求值。
 * 显式 DENY 优先于 ALLOW；无命中默认拒绝。
 */
public interface PolicyEvaluator {

    AuthzDecision evaluate(AuthzRequest request);
}
