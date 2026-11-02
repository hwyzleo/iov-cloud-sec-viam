package net.hwyz.iov.cloud.sec.viam.service.adapter.web.security;

/**
 * 已认证的服务调用方身份（SEC-VIAM-DSN-CR-001 / G-4）。
 * <p>
 * 由 {@link ServiceIdentityInterceptor} 验签后建立，仅承载可信身份映射字段；
 * 审计 caller 必须取自本上下文，禁止从请求体/请求头自报。
 * </p>
 *
 * @author hwyz_leo
 */
public record WorkloadContext(String clientId, String keyId, String audience) {

    /** 调用方标识（审计用） */
    public String clientId() {
        return clientId;
    }
}
