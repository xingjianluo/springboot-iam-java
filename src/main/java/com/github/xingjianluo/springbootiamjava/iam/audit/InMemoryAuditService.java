package com.github.xingjianluo.springbootiamjava.iam.audit;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import org.springframework.stereotype.Service;

/**
 * 基于 {@link CopyOnWriteArrayList} 的本地审计实现。
 *
 * <p>{@link #record(AuditEvent)} 是原子 append，并发场景下记录不丢失、顺序可追溯，
 * 事后可还原每一次判定的完整依据。通过 {@link #setWritable(boolean)} 可模拟
 * 审计存储不可写，用于验证“审计失败则受保护操作不放行”的失败关闭语义。
 */
@Service
public class InMemoryAuditService implements AuditService {

    private final CopyOnWriteArrayList<AuditEvent> events = new CopyOnWriteArrayList<>();
    private final AtomicBoolean writable = new AtomicBoolean(true);

    @Override
    public boolean record(AuditEvent event) {
        if (!writable.get()) {
            return false;
        }
        events.add(event);
        return true;
    }

    @Override
    public List<AuditEvent> findAll() {
        return List.copyOf(events);
    }

    @Override
    public void setWritable(boolean value) {
        writable.set(value);
    }
}
