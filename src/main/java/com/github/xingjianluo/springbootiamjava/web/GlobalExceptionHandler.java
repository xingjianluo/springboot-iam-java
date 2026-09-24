package com.github.xingjianluo.springbootiamjava.web;

import com.github.xingjianluo.springbootiamjava.iam.error.ErrorCode;
import com.github.xingjianluo.springbootiamjava.iam.error.IamException;
import com.github.xingjianluo.springbootiamjava.web.dto.Dtos.ErrorResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * 统一异常出口：业务异常映射为安全的错误码响应；
 * 其余未知异常一律收敛为 INTERNAL_ERROR，不透出底层细节。
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(IamException.class)
    public ResponseEntity<ErrorResponse> handleIam(IamException ex) {
        ErrorCode code = ex.errorCode();
        return ResponseEntity.status(code.httpStatus())
                .body(new ErrorResponse(code.name(), ex.getMessage()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleOther(Exception ex) {
        ErrorCode code = ErrorCode.INTERNAL_ERROR;
        return ResponseEntity.status(code.httpStatus())
                .body(new ErrorResponse(code.name(), code.publicMessage()));
    }
}
