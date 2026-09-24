package com.github.xingjianluo.springbootiamjava.iam.credential;

import com.github.xingjianluo.springbootiamjava.iam.model.Credential;
import java.util.function.UnaryOperator;

/**
 * 凭证的可变持有点：每个凭证 id 对应一个 StoredCredential，内置锁保证
 * 轮换（CAS）与撤销的原子性。凭证对象本身不可变。
 *
 * <p>检查与替换在同一把内置锁内完成，因此“撤销/过期/版本竞争”与“轮换”
 * 不可能交错产生歧义，撤销与在途轮换的结果确定。
 */
public class StoredCredential {

    private final Object lock = new Object();
    private Credential current;

    public StoredCredential(Credential initial) {
        this.current = initial;
    }

    /** 读取当前凭证的不可变视图。 */
    public Credential view() {
        synchronized (lock) {
            return current;
        }
    }

    /**
     * 基于期望版本的原子轮换。判定优先级：已撤销 &gt; 已过期 &gt; 版本竞争 &gt; 成功。
     *
     * @param expectedVersion 调用方读到的凭证版本
     * @param nowMillis       当前时间，用于在锁内完成过期判定，避免检查-执行竞态
     * @param generator       仅在确认可轮换时，依据当前凭证生成下一版凭证
     */
    public RotateResult compareAndRotate(long expectedVersion,
                                         long nowMillis,
                                         UnaryOperator<Credential> generator) {
        synchronized (lock) {
            Credential cur = current;
            if (cur.status() == com.github.xingjianluo.springbootiamjava.iam.model.CredentialStatus.REVOKED) {
                return RotateResult.of(RotateResult.Status.REVOKED);
            }
            if (nowMillis > cur.expiresAt()) {
                return RotateResult.of(RotateResult.Status.EXPIRED);
            }
            if (cur.version() != expectedVersion) {
                return RotateResult.of(RotateResult.Status.CONFLICT);
            }
            Credential next = generator.apply(cur);
            this.current = next;
            return RotateResult.success(next);
        }
    }

    /** 原子撤销：ACTIVE/ROTATED -> REVOKED；返回是否发生了状态变化。幂等。 */
    public boolean revoke() {
        synchronized (lock) {
            if (current.status() == com.github.xingjianluo.springbootiamjava.iam.model.CredentialStatus.REVOKED) {
                return false;
            }
            Credential c = current;
            current = new Credential(
                    c.credentialId(), c.secret(), c.subject(), c.roles(),
                    c.issuedAt(), c.expiresAt(),
                    com.github.xingjianluo.springbootiamjava.iam.model.CredentialStatus.REVOKED,
                    c.version());
            return true;
        }
    }
}
