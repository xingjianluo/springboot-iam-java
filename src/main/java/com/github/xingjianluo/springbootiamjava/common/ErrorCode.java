package com.github.xingjianluo.springbootiamjava.common;

import org.springframework.http.HttpStatus;

/**
 * 统一错误码：凭证无效 / 过期 / 已撤销 / 刷新冲突 / 策略拒绝 / 审计失败 / 内部错误可区分。
 */
public enum ErrorCode {

    CREDENTIAL_MISSING("CREDENTIAL_MISSING", HttpStatus.UNAUTHORIZED),
    CREDENTIAL_INVALID("CREDENTIAL_INVALID", HttpStatus.UNAUTHORIZED),
    CREDENTIAL_EXPIRED("CREDENTIAL_EXPIRED", HttpStatus.UNAUTHORIZED),
    CREDENTIAL_REVOKED("CREDENTIAL_REVOKED", HttpStatus.UNAUTHORIZED),
    REFRESH_CONFLICT("REFRESH_CONFLICT", HttpStatus.CONFLICT),
    AUTHZ_DENIED("AUTHZ_DENIED", HttpStatus.FORBIDDEN),
    AUTHZ_INDETERMINATE("AUTHZ_INDETERMINATE", HttpStatus.FORBIDDEN),
    AUDIT_UNAVAILABLE("AUDIT_UNAVAILABLE", HttpStatus.SERVICE_UNAVAILABLE),
    INTERNAL_ERROR("INTERNAL_ERROR", HttpStatus.INTERNAL_SERVER_ERROR),
    BAD_REQUEST("BAD_REQUEST", HttpStatus.BAD_REQUEST);

    private final String code;
    private final HttpStatus httpStatus;

    ErrorCode(String code, HttpStatus httpStatus) {
        this.code = code;
        this.httpStatus = httpStatus;
    }

    public String code() {
        return code;
    }

    public HttpStatus httpStatus() {
        return httpStatus;
    }
}
