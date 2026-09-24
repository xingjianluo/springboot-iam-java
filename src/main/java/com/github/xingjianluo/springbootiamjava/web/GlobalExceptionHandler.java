package com.github.xingjianluo.springbootiamjava.web;

import com.github.xingjianluo.springbootiamjava.audit.AuditUnavailableException;
import com.github.xingjianluo.springbootiamjava.common.ApiException;
import com.github.xingjianluo.springbootiamjava.common.ErrorCode;
import com.github.xingjianluo.springbootiamjava.common.ErrorResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * 对外只透出稳定错误码与安全消息；底层异常细节仅记录到服务端日志。
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<ErrorResponse> handleApi(ApiException ex) {
        log.warn("api failure code={} message={}", ex.errorCode().code(), ex.getMessage());
        return ResponseEntity.status(ex.errorCode().httpStatus())
                .body(new ErrorResponse(ex.errorCode().code(), ex.getMessage(), null));
    }

    @ExceptionHandler(AuditUnavailableException.class)
    public ResponseEntity<ErrorResponse> handleAudit(AuditUnavailableException ex) {
        // 不向调用方透出内部原因
        log.warn("audit unavailable: {}", ex.toString());
        return ResponseEntity.status(ErrorCode.AUDIT_UNAVAILABLE.httpStatus())
                .body(new ErrorResponse(ErrorCode.AUDIT_UNAVAILABLE.code(),
                        "audit facility is temporarily unavailable, request not committed", null));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> handleUnreadable(HttpMessageNotReadableException ex) {
        log.warn("malformed request: {}", ex.toString());
        return ResponseEntity.status(ErrorCode.BAD_REQUEST.httpStatus())
                .body(new ErrorResponse(ErrorCode.BAD_REQUEST.code(), "malformed request body", null));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleOther(Exception ex) {
        // 兜底：内部错误细节不外透
        log.error("unexpected internal failure", ex);
        return ResponseEntity.status(ErrorCode.INTERNAL_ERROR.httpStatus())
                .body(new ErrorResponse(ErrorCode.INTERNAL_ERROR.code(),
                        "an internal error occurred", null));
    }
}
