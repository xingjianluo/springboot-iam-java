package com.github.xingjianluo.springbootiamjava.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 基于本地内存的审计存储。
 *
 * <p>语义：
 * <ul>
 *     <li>{@link #setWritable(boolean)} 模拟审计后端故障：不可写时 append 抛
 *         {@link AuditUnavailableException}，由调用方在放行前检查（fail-closed）；</li>
 *     <li>写入在追加锁内完成，保证 append 的原子性与可还原性，事件带时间戳、输入与判定依据；</li>
 *     <li>findBySubject 返回快照副本，遍历期间不受并发写入影响；</li>
 *     <li>保留最近 {@value #MAX_EVENTS} 条，防止本地演示时内存无限增长。</li>
 * </ul>
 */
@Service
public class InMemoryAuditService implements AuditService {

    static final int MAX_EVENTS = 5_000;

    private static final Logger log = LoggerFactory.getLogger(InMemoryAuditService.class);

    private final CopyOnWriteArrayList<AuditEvent> events = new CopyOnWriteArrayList<>();
    private volatile boolean writable = true;
    private final Object appendLock = new Object();

    @Override
    public void append(AuditEvent event) {
        if (!writable) {
            // 内部细节只进日志，不外透
            log.warn("audit backend not writable, reject append action={} subject={}",
                    event.action(), event.subject());
            throw new AuditUnavailableException("audit backend is not writable");
        }
        synchronized (appendLock) {
            if (!writable) {
                log.warn("audit backend became not writable during append, reject action={} subject={}",
                        event.action(), event.subject());
                throw new AuditUnavailableException("audit backend is not writable");
            }
            events.add(event);
            int overflow = events.size() - MAX_EVENTS;
            for (int i = 0; i < overflow; i++) {
                events.remove(0);
            }
        }
    }

    @Override
    public List<AuditEvent> findBySubject(String subject) {
        List<AuditEvent> copy = new ArrayList<>();
        for (AuditEvent e : events) {
            if (subject == null || subject.equals(e.subject())) {
                copy.add(e);
            }
        }
        return List.copyOf(copy);
    }

    @Override
    public void setWritable(boolean writable) {
        synchronized (appendLock) {
            this.writable = writable;
        }
        log.info("audit writable switched to {}", writable);
    }

    @Override
    public boolean isWritable() {
        return writable;
    }

    @Override
    public void clear() {
        synchronized (appendLock) {
            events.clear();
            writable = true;
        }
    }
}
