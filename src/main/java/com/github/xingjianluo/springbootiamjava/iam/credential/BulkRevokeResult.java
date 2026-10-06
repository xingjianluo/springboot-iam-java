package com.github.xingjianluo.springbootiamjava.iam.credential;

import java.util.List;

/**
 * 账号级批量吊销的结果（不可变）。
 *
 * <p>语义：
 * <ul>
 *   <li>{@link Status#SUCCESS}：操作整体成功。本次新吊销、原本已吊销、已过期的凭证分别列出，
 *       三类互不重叠，已过期/已吊销的凭证被显式识别，不会被计为“漏网”或“误报”。</li>
 *   <li>{@link Status#NO_CREDENTIALS}：该账号名下没有任何凭证（从未签发），操作不产生任何状态变更。</li>
 *   <li>{@link Status#AUDIT_FAILED}：审计记录写不进去，操作整体失败，<b>不做任何状态变更</b>，
 *       不存在“一部分吊销了、一部分没有”的中间状态。</li>
 * </ul>
 *
 * @param status                     操作结论
 * @param subject                    目标账号
 * @param revokedCredentialIds       本次操作新吊销的凭证 id（含被刷新轮换过的凭证链的当前代）
 * @param alreadyRevokedCredentialIds 之前就已吊销的凭证 id（识别出来，不算本次动作）
 * @param expiredCredentialIds       已过期的凭证 id（识别出来，无需吊销）
 * @param revocationEpoch            该账号的处置代次：每次成功的批量吊销 +1，可用于确认处置已收敛
 */
public record BulkRevokeResult(
        Status status,
        String subject,
        List<String> revokedCredentialIds,
        List<String> alreadyRevokedCredentialIds,
        List<String> expiredCredentialIds,
        long revocationEpoch
) {

    public enum Status {
        SUCCESS,
        NO_CREDENTIALS,
        AUDIT_FAILED
    }

    public BulkRevokeResult {
        revokedCredentialIds = revokedCredentialIds == null ? List.of() : List.copyOf(revokedCredentialIds);
        alreadyRevokedCredentialIds = alreadyRevokedCredentialIds == null
                ? List.of() : List.copyOf(alreadyRevokedCredentialIds);
        expiredCredentialIds = expiredCredentialIds == null ? List.of() : List.copyOf(expiredCredentialIds);
    }

    public static BulkRevokeResult success(String subject, List<String> revoked,
                                           List<String> alreadyRevoked, List<String> expired,
                                           long revocationEpoch) {
        return new BulkRevokeResult(Status.SUCCESS, subject, revoked, alreadyRevoked, expired,
                revocationEpoch);
    }

    public static BulkRevokeResult of(Status status, String subject) {
        return new BulkRevokeResult(status, subject, List.of(), List.of(), List.of(), 0L);
    }
}
