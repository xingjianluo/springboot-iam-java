package com.github.xingjianluo.springbootiamjava.audit;

import java.util.List;

/**
 * 审计服务：append 不可写时必须抛出异常（fail-closed 由调用方在放行前判定）。
 */
public interface AuditService {

    /** 追加一条审计；审计后端不可写时抛出 {@link AuditUnavailableException}。 */
    void append(AuditEvent event);

    /** 本地查询审计轨迹（测试与排障用）。 */
    List<AuditEvent> findBySubject(String subject);

    /** 模拟审计后端故障 / 恢复。 */
    void setWritable(boolean writable);

    boolean isWritable();

    void clear();
}
