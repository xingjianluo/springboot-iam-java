package com.github.xingjianluo.springbootiamjava.authz;

import org.springframework.stereotype.Component;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 本地策略仓库。
 *
 * <p>策略变更（增删改）以"整体替换"方式提交：{@link #snapshot()} 永远返回一个不可变
 * {@link PolicySet} 引用，单次授权判定从评估开始到结束使用同一版本，
 * 不会观察到规则集合的中间状态。版本号单调递增，可写入审计判定依据。
 */
@Component
public class PolicyRepository {

    private final AtomicLongVersion version = new AtomicLongVersion();

    private record Snapshot(PolicySet set) {
    }

    private static final class AtomicLongVersion {
        private long value;

        private synchronized long next() {
            return ++value;
        }

        private synchronized long current() {
            return value;
        }
    }

    private final AtomicReference<PolicySet> current =
            new AtomicReference<>(new PolicySet(0L, List.of()));

    public PolicySet snapshot() {
        return current.get();
    }

    public PolicySet replaceAll(List<PolicyRule> rules) {
        List<PolicyRule> safe = List.copyOf(rules == null ? List.of() : rules);
        long nextVersion;
        synchronized (version) {
            nextVersion = version.next();
        }
        PolicySet next = new PolicySet(nextVersion, safe);
        current.set(next);
        return next;
    }

    /** 测试隔离。 */
    public void clear() {
        synchronized (version) {
            version.value = 0L;
        }
        current.set(new PolicySet(0L, List.of()));
    }
}
