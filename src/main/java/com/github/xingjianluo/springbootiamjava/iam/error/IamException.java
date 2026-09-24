package com.github.xingjianluo.springbootiamjava.iam.error;

/**
 * 业务异常：只携带可对外公开的错误码与安全说明，绝不包装底层异常细节向外透传。
 */
public class IamException extends RuntimeException {

    private final ErrorCode errorCode;

    public IamException(ErrorCode errorCode) {
        super(errorCode.publicMessage());
        this.errorCode = errorCode;
    }

    public IamException(ErrorCode errorCode, String publicMessage) {
        super(publicMessage);
        this.errorCode = errorCode;
    }

    public ErrorCode errorCode() {
        return errorCode;
    }
}
