package net.hwyz.iov.cloud.sec.viam.service.adapter.web.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.framework.common.constant.CustomHeaders;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * 服务调用方登记信息（SEC-VIAM-DSN-CR-001 / R1，内网互信修订 R2）。
 * <p>
 * 内网服务间互信：{@link ServiceIdentityInterceptor} 不再强制 X-Client-Id 映射与接口授权，
 * 请求一律放行。本类保留 clientId→路径前缀登记矩阵供审计识别调用方身份；
 * {@code requireAccess} 不再由拦截器调用，仅保留为可选的写端点策略与登记校验能力。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ServiceAccessPolicy {

    /** 服务接口根路径（全部安全服务端点） */
    public static final String SERVICE_API_ROOT = "/api/service/";

    private final ServiceIdentityProperties properties;

    /**
     * 解析请求携带的服务身份（X-Client-Id，平台内网信任链）。
     *
     * @param clientId 请求头 {@link CustomHeaders#CLIENT_ID} 的值（单一明确值；空/多值视为未知）
     * @return 归一化 clientId（已登记）；未登记返回 {@code null}
     */
    public String resolveClientId(String clientId) {
        if (clientId == null || clientId.isBlank()) {
            return null;
        }
        String normalized = clientId.trim();
        return properties.getAccess().containsKey(normalized) ? normalized : null;
    }

    /**
     * 校验调用方是否允许访问指定路径。
     *
     * @param clientId    已解析并登记的调用方身份
     * @param requestPath 请求路径
     * @throws ViamServiceException 越权（SERVICE_IDENTITY_PERMISSION_DENIED）
     */
    public void requireAccess(String clientId, String requestPath) {
        List<String> allowed = properties.getAccess().get(clientId);
        if (allowed == null || allowed.isEmpty()) {
            throw new ViamServiceException(
                    net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode.SERVICE_IDENTITY_PERMISSION_DENIED,
                    "调用方未登记任何接口权限: clientId=" + clientId);
        }
        for (String prefix : allowed) {
            if (requestPath != null && requestPath.startsWith(prefix)) {
                return;
            }
        }
        log.warn("服务身份越权访问: clientId={}, path={}", clientId, requestPath);
        throw new ViamServiceException(
                net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode.SERVICE_IDENTITY_PERMISSION_DENIED,
                "调用方无权访问: clientId=" + clientId + ", path=" + requestPath);
    }
}
