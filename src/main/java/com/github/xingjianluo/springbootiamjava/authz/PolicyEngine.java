package com.github.xingjianluo.springbootiamjava.authz;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Set;

/**
 * 授权判定引擎（RBAC + ABAC，显式 DENY 优先）。
 *
 * <p>评估规则（在单次快照内完成，边界确定）：
 * <ol>
 *     <li>取一次 {@link PolicySet} 快照和一次主体画像快照，整个评估只引用这两个对象；</li>
 *     <li>逐条匹配：subject / resource / action / 任一角色 / 主体属性 / 资源属性，
 *         字段为 null 表示通配；环境属性暂只记录不参与匹配；</li>
 *     <li>匹配的规则中若存在 DENY，立即拒绝（显式拒绝优先于一切 ALLOW）；</li>
 *     <li>否则取优先级最高的 ALLOW 放行；无任何匹配 => 默认拒绝；</li>
 *     <li>评估期间任何依赖异常 / 输入不完整 => INDETERMINATE，按拒绝处理（fail-closed）。</li>
 * </ol>
 */
@Component
public class PolicyEngine {

    private static final Logger log = LoggerFactory.getLogger(PolicyEngine.class);

    private final PolicyRepository policyRepository;

    public PolicyEngine(PolicyRepository policyRepository) {
        this.policyRepository = policyRepository;
    }

    public AuthorizationDecision evaluate(AuthorizationRequest request) {
        try {
            return doEvaluate(request);
        } catch (RuntimeException ex) {
            // 依赖异常不得放行：返回可区分的无法判定结论，细节仅入日志/审计
            log.warn("authorization evaluation failed, fail-closed. subject={}, resource={}, action={}, error={}",
                    request == null || request.subject() == null ? null : request.subject().subject(),
                    request == null ? null : request.resource(),
                    request == null ? null : request.action(),
                    ex.toString());
            long subjectVersion = request != null && request.subject() != null
                    ? request.subject().version() : -1L;
            long policyVersion = safePolicyVersion();
            String basis = "policyVersion=" + policyVersion
                    + ",subjectVersion=" + subjectVersion
                    + ",evaluationError=" + ex.getClass().getSimpleName();
            return new AuthorizationDecision(false, Effect.DENY, null,
                    policyVersion, subjectVersion,
                    AuthorizationDecision.REASON_INDETERMINATE, basis);
        }
    }

    private AuthorizationDecision doEvaluate(AuthorizationRequest request) {
        if (request == null || request.subject() == null
                || isBlank(request.resource()) || isBlank(request.action())) {
            throw new IllegalArgumentException("authorization request is incomplete");
        }
        SubjectProfileView view = SubjectProfileView.of(request.subject());

        PolicySet policySet = policyRepository.snapshot();
        long policyVersion = policySet.version();
        long subjectVersion = view.version();

        PolicyRule bestAllow = null;
        PolicyRule firstDeny = null;
        int matchedCount = 0;

        for (PolicyRule rule : policySet.rules()) {
            MatchResult mr = matches(rule, request, view);
            if (mr.matched()) {
                matchedCount++;
                if (rule.effect() == Effect.DENY && firstDeny == null) {
                    firstDeny = rule;
                    break; // 显式拒绝优先级最高，无需继续
                }
                if (rule.effect() == Effect.ALLOW
                        && (bestAllow == null || rule.priority() > bestAllow.priority())) {
                    bestAllow = rule;
                }
            }
        }

        String base = "policyVersion=" + policyVersion
                + ",subjectVersion=" + subjectVersion
                + ",matchedRules=" + matchedCount;
        if (firstDeny != null) {
            return new AuthorizationDecision(false, Effect.DENY, firstDeny.name(),
                    policyVersion, subjectVersion, AuthorizationDecision.REASON_DENY_RULE,
                    base + ",denyRule=" + firstDeny.name() + ",denyOverridesAllow=true");
        }
        if (bestAllow != null) {
            return new AuthorizationDecision(true, Effect.ALLOW, bestAllow.name(),
                    policyVersion, subjectVersion, "ALLOW_RULE",
                    base + ",allowRule=" + bestAllow.name() + ",priority=" + bestAllow.priority());
        }
        return new AuthorizationDecision(false, Effect.DENY, null,
                policyVersion, subjectVersion, AuthorizationDecision.REASON_DEFAULT_DENY,
                base + ",defaultDeny=true");
    }

    private long safePolicyVersion() {
        try {
            return policyRepository.snapshot().version();
        } catch (RuntimeException ignore) {
            return -1L;
        }
    }

    private MatchResult matches(PolicyRule rule, AuthorizationRequest req, SubjectProfileView view) {
        if (!matchesString(rule.subject(), view.subject())) {
            return MatchResult.NO;
        }
        if (!matchesString(rule.resource(), req.resource())) {
            return MatchResult.NO;
        }
        if (!matchesString(rule.action(), req.action())) {
            return MatchResult.NO;
        }
        if (rule.anyRole() != null && !rule.anyRole().isEmpty()) {
            boolean roleHit = rule.anyRole().stream().anyMatch(view.roles()::contains);
            if (!roleHit) {
                return MatchResult.NO;
            }
        }
        if (!matchesAttributes(rule.subjectAttributes(), view.attributes())) {
            return MatchResult.NO;
        }
        if (!matchesAttributes(rule.resourceAttributes(),
                req.resourceAttributes() == null ? Map.of() : req.resourceAttributes())) {
            return MatchResult.NO;
        }
        return MatchResult.YES;
    }

    private boolean matchesString(String pattern, String value) {
        return pattern == null || "*".equals(pattern) || pattern.equals(value);
    }

    private boolean matchesAttributes(Map<String, String> required, Map<String, String> actual) {
        if (required == null || required.isEmpty()) {
            return true;
        }
        for (Map.Entry<String, String> e : required.entrySet()) {
            String actualValue = actual.get(e.getKey());
            String expected = e.getValue();
            if (expected == null) {
                if (actualValue != null) {
                    return false;
                }
                continue;
            }
            if (actualValue == null) {
                return false;
            }
            if ("*".equals(expected)) {
                continue;
            }
            if (!expected.equals(actualValue)) {
                return false;
            }
        }
        return true;
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    private record MatchResult(boolean matched) {
        static final MatchResult YES = new MatchResult(true);
        static final MatchResult NO = new MatchResult(false);
    }

    /** 解耦 record 访问，便于异常定位。 */
    private record SubjectProfileView(String subject, Set<String> roles,
                                     Map<String, String> attributes, long version) {
        static SubjectProfileView of(com.github.xingjianluo.springbootiamjava.subject.SubjectProfile p) {
            return new SubjectProfileView(p.subject(), p.roles(), p.attributes(), p.version());
        }
    }
}
