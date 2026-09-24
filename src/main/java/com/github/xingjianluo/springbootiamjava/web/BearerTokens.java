package com.github.xingjianluo.springbootiamjava.web;

/**
 * 从 Authorization 头提取 Bearer 凭证。
 * 头缺失/方案不匹配/凭证为空都返回 null，由入口映射为 CREDENTIAL_MISSING。
 */
public final class BearerTokens {

    private static final String PREFIX = "Bearer ";

    private BearerTokens() {
    }

    public static String extract(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith(PREFIX)) {
            return null;
        }
        String token = authorizationHeader.substring(PREFIX.length()).trim();
        return token.isEmpty() ? null : token;
    }
}
