package com.github.xingjianluo.springbootiamjava.tests.support;

import com.github.xingjianluo.springbootiamjava.iam.time.Clock;

/** 可控时间源：测试可任意推进时间以确定地触发过期，无需真实等待。 */
public class ManualClock implements Clock {

    private volatile long now;

    public ManualClock(long start) {
        this.now = start;
    }

    @Override
    public long nowMillis() {
        return now;
    }

    public void advance(long deltaMillis) {
        this.now += deltaMillis;
    }

    public void set(long value) {
        this.now = value;
    }
}
