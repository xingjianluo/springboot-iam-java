package com.github.xingjianluo.springbootiamjava.iam.authz;

import com.github.xingjianluo.springbootiamjava.iam.model.AuthzSnapshot;
import com.github.xingjianluo.springbootiamjava.iam.model.Policy;
import com.github.xingjianluo.springbootiamjava.iam.model.SubjectAttributes;

/**
 * 授权状态存储：策略与主体属性的变更以修订号原子推进，
 * 任意时刻只能读到一致的不可变快照。
 */
public interface AuthzStore {

    /** 读取当前一致快照。 */
    AuthzSnapshot snapshot();

    /** 新增或更新策略（按 policyId），原子推进修订号。 */
    void upsertPolicy(Policy policy);

    /** 删除策略，原子推进修订号。 */
    boolean removePolicy(String policyId);

    /** 新增或更新主体属性，原子推进修订号。 */
    void upsertSubject(SubjectAttributes subject);

    /** 测试支持：模拟存储故障（snapshot 抛错），用于验证失败关闭语义。 */
    void setFaulty(boolean faulty);

    /** 测试/本地验证支持：清空。 */
    void clear();
}
