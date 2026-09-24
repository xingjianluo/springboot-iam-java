package com.github.xingjianluo.springbootiamjava.common;

/**
 * 业务异常：只携带稳定错误码与可对外展示的安全消息，不携带底层堆栈。
 */
public class ApiException extends RuntimeException {

    private final ErrorCode errorCode;

    public ApiException(ErrorCode errorCode, String safeMessage) {
        super(safeMessage);
        this.errorCode = errorCode;
    }

    public ErrorCode errorCode() {
        return errorCode;
    }
}
