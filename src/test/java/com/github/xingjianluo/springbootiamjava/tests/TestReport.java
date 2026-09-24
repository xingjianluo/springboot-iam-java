package com.github.xingjianluo.springbootiamjava.tests;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** 测试日志：打印输入、判定依据与结果，便于本地还原链路。 */
public final class TestReport {

    private static final Logger LOG = LoggerFactory.getLogger("IAM-TEST");

    private TestReport() {
    }

    public static void log(String title, String detail) {
        LOG.info("[{}] {}", title, detail);
        System.out.println(">>> [" + title + "] " + detail);
    }
}
