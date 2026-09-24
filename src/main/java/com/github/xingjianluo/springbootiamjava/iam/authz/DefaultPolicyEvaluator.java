package com.github.xingjianluo.springbootiamjava.iam.authz;

import com.github.xingjianluo.springbootiamjava.iam.error.ErrorCode;
import com.github.xingjianluo.springbootiamjava.iam.error.IamException;
import com.github.xingjianluo.springbootiamjava.iam.model.AuthzDecision;
import com.github.xingjianluo.springbootiamjava.iam.model.AuthzRequest;
import com.github.xingjianluo.springbootiamjava.iam.model.AuthzSnapshot;
import com.github.xingjianluo.springbootiamjava.iam.model.DecisionReason;
import com.github.xingjianluo.springbootiamjava.iam.model.Policy;
import com.github.xingjianluo.springbootiamjava.iam.model.PolicyEffect;
import com.github.xingjianluo.springbootiamjava.iam.model.SubjectAttributes;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Service;

/**
 * 默认策略判定器。
 *
 * <p>判定规则：
 * <ol>
 *   <li>只在单个 {@link AuthzSnapshot} 上求值，保证策略/属性变更的生效边界一致；</li>
 *   <li>命中条件全部满足才算命中（资源前缀 + 动作 + 任一角色 + 全部属性等值）；</li>
 *   <li>显式 DENY 优先于 ALLOW：只要存在命中的 DENY 即拒绝；</li>
 *   <li>无命中策略时默认拒绝（NO_MATCHING_POLICY）；</li>
 *   <li>读取快照失败等依赖异常按失败关闭抛出 AUTHZ_INDETERMINATE。</li>
 * </ol>
 */
@Service
public class DefaultPolicyEvaluator implements PolicyEvaluator {

    private final AuthzStore store;

    public DefaultPolicyEvaluator(AuthzStore store) {
        this.store = store;
    }

    @Override
    public AuthzDecision evaluate(AuthzRequest request) {
        final AuthzSnapshot snapshot;
        try {
            snapshot = store.snapshot();
        } catch (IamException e) {
            throw e;
        } catch (RuntimeException e) {
            // 不向上透传底层异常，统一收敛为可解释的失败关闭原因。
            throw new IamException(ErrorCode.AUTHZ_INDETERMINATE);
        }

        List<String> allowIds = new java.util.ArrayList<>();
        List<String> denyIds = new java.util.ArrayList<>();
        // 主体属性从当前一致快照解析：属性变更随快照修订一起生效，避免调用方伪造或滞后。
        SubjectAttributes subject = snapshot.subjects().get(request.subject());
        Map<String, String> subjectAttributes = subject == null ? Map.of() : subject.attributes();
        AuthzRequest effective = new AuthzRequest(
                request.subject(), request.roles(), subjectAttributes,
                request.resource(), request.action());
        for (Policy policy : snapshot.policies()) {
            if (matches(policy, effective)) {
                if (policy.effect() == PolicyEffect.DENY) {
                    denyIds.add(policy.policyId());
                } else {
                    allowIds.add(policy.policyId());
                }
            }
        }

        DecisionReason reason;
        boolean allow;
        List<String> matched;
        if (!denyIds.isEmpty()) {
            allow = false;
            reason = DecisionReason.EXPLICIT_DENY;
            matched = denyIds;
        } else if (!allowIds.isEmpty()) {
            allow = true;
            reason = DecisionReason.ALLOW;
            matched = allowIds;
        } else {
            allow = false;
            reason = DecisionReason.NO_MATCHING_POLICY;
            matched = List.of();
        }
        return new AuthzDecision(allow, reason, List.copyOf(matched), snapshot.revision());
    }

    private boolean matches(Policy policy, AuthzRequest request) {
        if (!resourceMatches(policy.resourcePrefix(), request.resource())) {
            return false;
        }
        if (policy.action() != null && !policy.action().equals(request.action())) {
            return false;
        }
        if (policy.anyOfRoles() != null && !policy.anyOfRoles().isEmpty()) {
            List<String> roles = request.roles() == null ? List.of() : request.roles();
            boolean roleHit = policy.anyOfRoles().stream().anyMatch(roles::contains);
            if (!roleHit) {
                return false;
            }
        }
        if (policy.attributeEquals() != null && !policy.attributeEquals().isEmpty()) {
            Map<String, String> attrs =
                    request.subjectAttributes() == null ? Map.of() : request.subjectAttributes();
            for (Map.Entry<String, String> cond : policy.attributeEquals().entrySet()) {
                if (!cond.getValue().equals(attrs.get(cond.getKey()))) {
                    return false;
                }
            }
        }
        return true;
    }

    private boolean resourceMatches(String prefix, String resource) {
        if (prefix == null || prefix.isEmpty() || "*".equals(prefix)) {
            return true;
        }
        if (resource == null) {
            return false;
        }
        // 支持显式通配前缀（docs*）与普通路径前缀（docs/）两种写法。
        if (prefix.endsWith("*")) {
            return resource.startsWith(prefix.substring(0, prefix.length() - 1));
        }
        return resource.startsWith(prefix) || prefix.equals(resource);
    }
}
