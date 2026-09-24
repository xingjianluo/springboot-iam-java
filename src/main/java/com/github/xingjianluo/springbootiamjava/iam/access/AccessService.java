package com.github.xingjianluo.springbootiamjava.iam.access;

/**
 * 访问编排：串联 凭证校验 -> 授权判定 -> 审计落盘。
 * 审计不可写时，任何“本应放行”的请求都会失败关闭。
 */
public interface AccessService {

    AccessResult access(String secret, String resource, String action);
}
