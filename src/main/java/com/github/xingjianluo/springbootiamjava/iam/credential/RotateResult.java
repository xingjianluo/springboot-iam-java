package com.github.xingjianluo.springbootiamjava.iam.credential;

import com.github.xingjianluo.springbootiamjava.iam.model.Credential;

/**
 * 并发安全轮换的结果。
 * SUCCESS：轮换成功，携带新凭证；
 * REVOKED：凭证已被撤销，拒绝轮换；
 * EXPIRED：凭证已过期，拒绝轮换；
 * CONFLICT：凭证已被另一个并发请求轮换（版本不匹配）；
 * INVALID：密文不存在或已失效（旧密文轮换后立即查不到）。
 */
public record RotateResult(Status status, Credential credential) {

    public enum Status {
        SUCCESS,
        REVOKED,
        EXPIRED,
        CONFLICT,
        INVALID
    }

    public static RotateResult success(Credential c) {
        return new RotateResult(Status.SUCCESS, c);
    }

    public static RotateResult of(Status status) {
        return new RotateResult(status, null);
    }
}
