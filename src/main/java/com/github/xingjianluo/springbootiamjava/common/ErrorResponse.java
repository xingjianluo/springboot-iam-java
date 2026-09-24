package com.github.xingjianluo.springbootiamjava.common;

/**
 * 对外错误响应体（不含底层异常细节）。
 */
public record ErrorResponse(String errorCode, String message, String traceId) {
}
