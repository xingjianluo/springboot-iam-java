package com.github.xingjianluo.springbootiamjava.credential;

import java.security.SecureRandom;
import java.util.HexFormat;

/**
 * 本地模拟用安全随机标识：不依赖任何外部凭据服务。
 */
public final class Identifiers {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final HexFormat HEX = HexFormat.of();

    private Identifiers() {
    }

    public static String newChainId() {
        return "chain-" + randomHex(12);
    }

    public static String newToken() {
        return "cred-" + randomHex(24);
    }

    private static String randomHex(int bytes) {
        byte[] buf = new byte[bytes];
        RANDOM.nextBytes(buf);
        return HEX.formatHex(buf);
    }
}
