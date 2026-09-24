package com.github.xingjianluo.springbootiamjava.credential;

import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 一条凭证链：同一次签发后经多次轮换产生的凭证共享 chainId。
 * 撤销链上任一凭证即撤销整条链（含已轮换的旧凭证）。
 */
public class CredentialChain {

    private final String chainId;
    private final String subject;
    // 公平锁：竞争时按排队顺序获取，使"撤销 vs 在途请求"的交错顺序确定、可测试
    private final ReentrantLock lock = new ReentrantLock(true);
    private final LinkedList<String> versionTokens = new LinkedList<>();
    private volatile boolean chainRevoked;
    private volatile long revokedAtMillis;
    private volatile String revokeReason;

    public CredentialChain(String chainId, String subject) {
        this.chainId = chainId;
        this.subject = subject;
    }

    public String chainId() { return chainId; }
    public String subject() { return subject; }
    public ReentrantLock lock() { return lock; }
    public List<String> versionTokens() { return versionTokens; }
    public boolean chainRevoked() { return chainRevoked; }
    public long revokedAtMillis() { return revokedAtMillis; }
    public String revokeReason() { return revokeReason; }

    /** 必须在持有 {@link #lock()} 时调用：整条链幂等撤销。 */
    public void markChainRevoked(long atMillis, String reason) {
        if (!chainRevoked) {
            this.chainRevoked = true;
            this.revokedAtMillis = atMillis;
            this.revokeReason = reason;
        }
    }
}
