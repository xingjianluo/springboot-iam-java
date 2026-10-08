package com.github.xingjianluo.springbootiamjava.iam.credential;

import com.github.xingjianluo.springbootiamjava.iam.model.Credential;
import java.util.List;

/**
 * 账号级批量吊销的分类计划：存储层在变更锁内对该主体全部凭证做完分类后，
 * 把三类结果整体交给审计钩子，保证审计记录与真实分类逐条一致。
 *
 * @param toRevoke       本次将吊销的仍有效凭证（当前视图）
 * @param alreadyRevoked 操作前已处于 REVOKED 的凭证（识别，不重复计入）
 * @param expired        操作前已过期的凭证（识别，不吊销也不计入）
 */
public record RevokePlan(List<Credential> toRevoke,
                         List<Credential> alreadyRevoked,
                         List<Credential> expired) {
}
