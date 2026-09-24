package com.github.xingjianluo.springbootiamjava.iam.model;

/**
 * 凭证的不可变快照，所有生命周期判定都基于某一时刻的快照进行。
 *
 * @param credentialId 凭证稳定标识（轮换后保持不变，形成凭证链）
 * @param secret       当次凭证密文（每次轮换都会变化）
 * @param subject      归属主体
 * @param roles        签发时绑定的角色快照
 * @param issuedAt     签发时间（epoch 毫秒）
 * @param expiresAt    过期时间（epoch 毫秒）
 * @param status       当前状态
 * @param version      凭证版本，从 0 开始，每轮换一次加一
 */
public record Credential(
        String credentialId,
        String secret,
        String subject,
        java.util.List<String> roles,
        long issuedAt,
        long expiresAt,
        CredentialStatus status,
        long version
) {
}
