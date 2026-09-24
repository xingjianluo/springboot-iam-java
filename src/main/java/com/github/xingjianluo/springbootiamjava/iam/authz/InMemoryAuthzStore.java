package com.github.xingjianluo.springbootiamjava.iam.authz;

import com.github.xingjianluo.springbootiamjava.iam.error.ErrorCode;
import com.github.xingjianluo.springbootiamjava.iam.error.IamException;
import com.github.xingjianluo.springbootiamjava.iam.model.AuthzSnapshot;
import com.github.xingjianluo.springbootiamjava.iam.model.Policy;
import com.github.xingjianluo.springbootiamjava.iam.model.SubjectAttributes;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.springframework.stereotype.Repository;

/**
 * 基于不可变快照 + {@link AtomicReference} 的内存授权存储。
 *
 * <p>任意一次变更都构造一个全新的 {@link AuthzSnapshot} 并原子发布，修订号单调递增。
 * 一次判定只读取一个快照，因此策略/角色（主体属性）变更不会产生半新半旧的视图：
 * 变更前的请求一律按旧快照收敛，变更后的请求一律按新快照收敛。
 */
@Repository
public class InMemoryAuthzStore implements AuthzStore {

    private final AtomicReference<AuthzSnapshot> current =
            new AtomicReference<>(new AuthzSnapshot(0L, List.of(), Map.of()));
    private final AtomicBoolean faulty = new AtomicBoolean(false);

    @Override
    public AuthzSnapshot snapshot() {
        if (faulty.get()) {
            // 依赖异常：调用方必须按失败关闭语义处理（AUTHZ_INDETERMINATE）。
            throw new IamException(ErrorCode.AUTHZ_INDETERMINATE);
        }
        return current.get();
    }

    @Override
    public void upsertPolicy(Policy policy) {
        current.updateAndGet(prev -> {
            Map<String, Policy> byId = new LinkedHashMap<>();
            for (Policy p : prev.policies()) {
                byId.put(p.policyId(), p);
            }
            byId.put(policy.policyId(), policy);
            return new AuthzSnapshot(prev.revision() + 1, List.copyOf(byId.values()), prev.subjects());
        });
    }

    @Override
    public boolean removePolicy(String policyId) {
        boolean[] changed = {false};
        current.updateAndGet(prev -> {
            List<Policy> kept = new ArrayList<>();
            for (Policy p : prev.policies()) {
                if (!p.policyId().equals(policyId)) {
                    kept.add(p);
                } else {
                    changed[0] = true;
                }
            }
            if (!changed[0]) {
                return prev;
            }
            return new AuthzSnapshot(prev.revision() + 1, List.copyOf(kept), prev.subjects());
        });
        return changed[0];
    }

    @Override
    public void upsertSubject(SubjectAttributes subject) {
        current.updateAndGet(prev -> {
            Map<String, SubjectAttributes> subjects = new HashMap<>(prev.subjects());
            // 快照内的主体以当前修订号标记，保证属性读取与策略判定基于同一版本视图。
            subjects.put(subject.subject(),
                    new SubjectAttributes(subject.subject(), Map.copyOf(subject.attributes()), prev.revision() + 1));
            return new AuthzSnapshot(prev.revision() + 1, prev.policies(), Map.copyOf(subjects));
        });
    }

    @Override
    public void setFaulty(boolean value) {
        faulty.set(value);
    }

    @Override
    public void clear() {
        current.set(new AuthzSnapshot(0L, List.of(), Map.of()));
        faulty.set(false);
    }
}
