package com.github.xingjianluo.springbootiamjava.iam.account;

/**
 * 账号维度会话（有效凭证）的可辨识视图。
 *
 * @param credentialId 凭证稳定标识（轮换链不变）
 * @param version      当前凭证版本，每次刷新 +1
 * @param issuedAt     当前版本签发时间（epoch 毫秒）
 * @param expiresAt    当前版本过期时间（epoch 毫秒）
 */
public record SessionView(String credentialId, long version, long issuedAt, long expiresAt) {
}
