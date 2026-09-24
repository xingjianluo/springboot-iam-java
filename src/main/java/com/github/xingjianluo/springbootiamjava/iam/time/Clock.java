package com.github.xingjianluo.springbootiamjava.iam.time;

/**
 * 时间源抽象，便于在测试中控制过期判定，避免依赖真实等待。
 */
public interface Clock {

    /** 当前时间（epoch 毫秒）。 */
    long nowMillis();
}
