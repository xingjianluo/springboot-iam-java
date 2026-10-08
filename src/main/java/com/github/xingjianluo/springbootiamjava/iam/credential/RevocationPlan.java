package com.github.xingjianluo.springbootiamjava.iam.credential;

import com.github.xingjianluo.springbootiamjava.iam.model.Credential;
import java.util.List;

/**
 * 账号级批量吊销在存储变更锁内完成的一次确定性分类快照。
 *
 * <p>账号名下的每条凭证恰好归入三类之一，既给数量也给稳定标识，供审计钩子在落变更前
 * 完整记录“本次识别出了哪几类、分别是哪几条”，使审计记录与接口返回、会话查询可互相核对：
 * <ul>
 *   <li>{@link #toRevoke()}：本次仍有效、将被吊销的凭证（吊销前视图）；</li>
 *   <li>{@link #alreadyRevoked()}：操作之前就已处于 REVOKED 的凭证；</li>
 *   <li>{@link #expired()}：操作之前就已过期（ACTIVE 但 now &gt; expiresAt）的凭证。</li>
 * </ul>
 *
 * @param toRevoke       本次将吊销的有效凭证视图（吊销前），非 null
 * @param alreadyRevoked 操作前已吊销的凭证视图，非 null
 * @param expired        操作前已过期的凭证视图，非 null
 */
public record RevocationPlan(List<Credential> toRevoke,
                             List<Credential> alreadyRevoked,
                             List<Credential> expired) {

    public RevocationPlan {
        toRevoke = List.copyOf(toRevoke);
        alreadyRevoked = List.copyOf(alreadyRevoked);
        expired = List.copyOf(expired);
    }

    public int toRevokeCount() {
        return toRevoke.size();
    }

    public int alreadyRevokedCount() {
        return alreadyRevoked.size();
    }

    public int expiredCount() {
        return expired.size();
    }
}
