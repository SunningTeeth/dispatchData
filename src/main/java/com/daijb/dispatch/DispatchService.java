package com.daijb.dispatch;

/**
 * @author daijb
 * @date 2021/2/24 13:33
 */
public interface DispatchService {

    static enum LogType {
        /**
         * 网络威胁
         */
        csp_netthreat,
        /**
         * 恶意代码
         */
        csp_malware,
        /**
         * 威胁情报
         */
        csp_ti,
        /**
         * 异常行为
         */
        csp_event,
        /**
         * 用户自定义
         */
        csp_user,
        /**
         * HTTP数据
         */
        csp_http,
        /**
         *文件检查结果日志
         */
        csp_filechecking
    }
}
