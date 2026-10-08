package com.github.xingjianluo.springbootiamjava.iam.account;

import java.util.List;

/**
 * 账号级批量吊销的结果。
 *
 * @param operationId              本次批量操作标识（同时写入审计，便于确认处置已收敛）
 * @param subject                  账号主体
 * @param revokedCount             本次实际吊销的有效凭证数
 * @param alreadyRevokedCount      操作前就已吊销的凭证数（识别出来，不算漏网）
 * @param expiredCount             操作前就已过期的凭证数（识别出来，不算误报）
 * @param revokedCredentialIds     本次吊销的凭证稳定 id 列表
 * @param alreadyRevokedCredentialIds 操作前就已吊销的凭证稳定 id 列表
 * @param expiredCredentialIds     操作前就已过期的凭证稳定 id 列表
 */
public record BatchRevocationResult(String operationId, String subject,
                                    int revokedCount, int alreadyRevokedCount, int expiredCount,
                                    List<String> revokedCredentialIds,
                                    List<String> alreadyRevokedCredentialIds,
                                    List<String> expiredCredentialIds) {
}
