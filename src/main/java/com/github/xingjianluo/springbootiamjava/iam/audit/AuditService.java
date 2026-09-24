package com.github.xingjianluo.springbootiamjava.iam.audit;

import java.util.List;

/**
 * 审计服务：受保护操作的判定必须落审计；写入失败时上层需失败关闭。
 */
public interface AuditService {

    /**
     * 追加一条审计记录。
     * @return true 写入成功；false 审计子系统不可写
     */
    boolean record(AuditEvent event);

    /** 读取全部审计记录（本地验证用）。 */
    List<AuditEvent> findAll();

    /** 测试支持：模拟审计不可写。 */
    void setWritable(boolean writable);
}
