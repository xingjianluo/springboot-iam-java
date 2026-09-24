package com.github.xingjianluo.springbootiamjava.iam.time;

import org.springframework.stereotype.Component;

/** 基于系统墙钟的默认时间源。 */
@Component
public class SystemClock implements Clock {

    @Override
    public long nowMillis() {
        return System.currentTimeMillis();
    }
}
