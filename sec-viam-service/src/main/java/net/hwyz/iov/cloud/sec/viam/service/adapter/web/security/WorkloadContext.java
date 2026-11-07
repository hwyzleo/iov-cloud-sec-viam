package net.hwyz.iov.cloud.sec.viam.service.adapter.web.security;

/**
 * 服务调用方审计身份（SEC-VIAM-DSN-CR-001 / R1，内网互信修订 R2）。
 * <p>
 * 由 {@link ServiceIdentityInterceptor} 基于请求头 {@code X-Client-Id} 承载（不强制映射/授权），
 * 缺失/未知时 clientId 为 {@code null}；审计 caller 必须取自本上下文，禁止从请求体自报。
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
