package com.github.xingjianluo.springbootiamjava.subject;

import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 本地主体目录。
 *
 * <p>一致性语义：
 * <ul>
 *     <li>每次 upsert 产生新版本号，画像整体替换为不可变 {@link SubjectProfile}；</li>
 *     <li>读路径拿到的是引用快照，单次授权判定内不会观察到半更新状态；</li>
 *     <li>主体不存在时返回空画像（无角色、无属性、版本 0），默认无任何权限。</li>
 * </ul>
 */
@Component
public class SubjectDirectory {

    private static final class Held {
        private final AtomicLong version = new AtomicLong(0);
        private volatile SubjectProfile profile;

        private SubjectProfile snapshotOrEmpty(String subject) {
            SubjectProfile p = profile;
            return p != null ? p : new SubjectProfile(subject, Set.of(), Map.of(), 0L);
        }
    }

    private final ConcurrentMap<String, Held> subjects = new ConcurrentHashMap<>();

    public SubjectProfile snapshot(String subject) {
        Held held = subjects.get(subject);
        if (held == null) {
            return new SubjectProfile(subject, Set.of(), Map.of(), 0L);
        }
        return held.snapshotOrEmpty(subject);
    }

    public SubjectProfile upsert(String subject, Set<String> roles, Map<String, String> attributes) {
        if (subject == null || subject.isBlank()) {
            throw new IllegalArgumentException("subject must not be blank");
        }
        Held held = subjects.computeIfAbsent(subject, s -> new Held());
        synchronized (held) {
            long nextVersion = held.version.incrementAndGet();
            held.profile = new SubjectProfile(
                    subject,
                    Set.copyOf(roles == null ? Set.of() : roles),
                    Map.copyOf(attributes == null ? Map.of() : attributes),
                    nextVersion);
            return held.profile;
        }
    }

    public long currentVersion(String subject) {
        Held held = subjects.get(subject);
        return held == null ? 0L : held.version.get();
    }

    /** 测试隔离。 */
    public void clear() {
        subjects.clear();
    }
}
