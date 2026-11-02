package net.hwyz.iov.cloud.sec.viam.api.constant;

/**
 * 访问失效类型（SEC-VIAM-DSN-CR-001 / FR-VIAM-008 / G-3）。
 *
 * @author hwyz_leo
 */
public enum AccessInvalidationType {

    /** 单连接处置：针对指定会话/generation；不得误断更新的合法会话 */
    CONNECTION_DISPOSAL,

    /** 主体/凭据/绑定持续安全状态撤销：不因重连换 generation 逃逸 */
    PRINCIPAL_REVOCATION
}
