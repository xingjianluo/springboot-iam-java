package com.github.xingjianluo.springbootiamjava.iam.error;

import org.springframework.http.HttpStatus;

/**
 * 对外可见的、可区分的失败原因码。
 * 每个错误码都带有固定的公开说明与 HTTP 状态，不依赖底层异常信息。
 */
public enum ErrorCode {

    /** 凭证不存在、格式非法或已被轮换（旧凭证立即失效）。 */
    INVALID_CREDENTIAL("credential is invalid", HttpStatus.UNAUTHORIZED),
    /** 凭证已超过有效期。 */
    CREDENTIAL_EXPIRED("credential has expired", HttpStatus.UNAUTHORIZED),
    /** 凭证已被显式撤销。 */
    CREDENTIAL_REVOKED("credential has been revoked", HttpStatus.UNAUTHORIZED),
    /** 同一凭证并发刷新，只有一次成功，其余竞争失败。 */
    REFRESH_CONFLICT("credential was refreshed by a concurrent request", HttpStatus.CONFLICT),
    /** 策略显式拒绝或无匹配策略（默认拒绝）。 */
    POLICY_DENIED("access denied by policy", HttpStatus.FORBIDDEN),
    /** 授权依赖异常，无法做出判定（失败关闭）。 */
    AUTHZ_INDETERMINATE("authorization decision could not be made", HttpStatus.INTERNAL_SERVER_ERROR),
    /** 审计不可写，受保护操作不得放行。 */
    AUDIT_UNAVAILABLE("audit subsystem is unavailable", HttpStatus.SERVICE_UNAVAILABLE),
    /** 请求体或参数非法。 */
    MALFORMED_REQUEST("malformed request", HttpStatus.BAD_REQUEST),
    /** 撤销/查询时引用了不存在的凭证 id。 */
    UNKNOWN_CREDENTIAL_ID("credential id not found", HttpStatus.NOT_FOUND),
    /** 账号级批量吊销时，该账号当前没有任何仍生效的凭证（与系统不可用可区分）。 */
    NO_ACTIVE_CREDENTIALS("no active credentials for subject", HttpStatus.NOT_FOUND),
    /** 兜底内部错误，对外不暴露细节。 */
    INTERNAL_ERROR("internal server error", HttpStatus.INTERNAL_SERVER_ERROR);

    private final String publicMessage;
    private final HttpStatus httpStatus;

    ErrorCode(String publicMessage, HttpStatus httpStatus) {
        this.publicMessage = publicMessage;
        this.httpStatus = httpStatus;
    }

    public String publicMessage() {
        return publicMessage;
    }

    public HttpStatus httpStatus() {
        return httpStatus;
    }
}
