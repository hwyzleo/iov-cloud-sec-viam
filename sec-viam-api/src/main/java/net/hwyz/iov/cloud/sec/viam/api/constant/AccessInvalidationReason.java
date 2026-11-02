package net.hwyz.iov.cloud.sec.viam.api.constant;

/**
 * 访问失效原因（SEC-VIAM-DSN-CR-001 / FR-VIAM-008 / G-3）。
 *
 * @author hwyz_leo
 */
public enum AccessInvalidationReason {

    /** 安全封禁 */
    BLOCK,

    /** 退役 */
    RETIRE,

    /** 证书/密钥吊销 */
    REVOKE,

    /** 解绑 */
    UNBIND,

    /** 换件（新绑定取代旧绑定） */
    REPLACEMENT,

    /** 单连接处置（会话/generation 级） */
    CONNECTION_DISPOSAL
}
