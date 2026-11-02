package net.hwyz.iov.cloud.sec.viam.service.adapter.web.security;

/**
 * 已映射的服务调用方身份（SEC-VIAM-DSN-CR-001 / R1）。
 * <p>
 * 由 {@link ServiceIdentityInterceptor} 基于 {@code X-Client-Id} 映射/授权后建立，
 * 仅承载平台受控内网的服务身份约定；审计 caller 必须取自本上下文，禁止从请求体自报。
 * 不宣称逐请求密码学来源验证（见 CR-001 R1.2）。
 * </p>
 *
 * @author hwyz_leo
 */
public record WorkloadContext(String clientId, String requestPath) {

    /** 调用方标识（审计用） */
    public String clientId() {
        return clientId;
    }
}
