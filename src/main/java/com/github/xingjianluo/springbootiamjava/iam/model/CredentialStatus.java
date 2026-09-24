package com.github.xingjianluo.springbootiamjava.iam.model;

/**
 * 凭证生命周期状态。
 * ACTIVE：有效；ROTATED：已被刷新轮换，旧凭证立即失效；REVOKED：已显式撤销。
 */
public enum CredentialStatus {
    ACTIVE,
    ROTATED,
    REVOKED
}
