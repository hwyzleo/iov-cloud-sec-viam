package net.hwyz.iov.cloud.sec.viam.service.adapter.web.security;

import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * 服务接口授权矩阵（G-4）。
 * <p>
 * 按调用方身份（clientId）+ 请求路径前缀判定接口权限；身份有效但越权访问一律拒绝。
 * 默认仅 VAGW 可访问已迁服务接口；OAPI/MES 等调用方按登记路径前缀显式配置。
 * </p>
 *
 * @author hwyz_leo
 */
@Component
public class ServiceAccessPolicy {

    /** 服务接口根路径（全部安全服务端点） */
    public static final String SERVICE_API_ROOT = "/api/service/";

    private final ServiceIdentityProperties properties;

    public ServiceAccessPolicy(ServiceIdentityProperties properties) {
        this.properties = properties;
    }

    /**
     * 校验调用方是否允许访问指定路径。
     *
     * @throws ViamServiceException 越权（702705）
     */
    public void requireAccess(String clientId, String requestPath) {
        if (clientId == null) {
            throw new ViamServiceException(ViamErrorCode.SERVICE_IDENTITY_MISSING);
        }
        List<String> allowed = properties.getAccess().get(clientId);
        if (allowed == null || allowed.isEmpty()) {
            throw new ViamServiceException(ViamErrorCode.SERVICE_IDENTITY_PERMISSION_DENIED,
                    "调用方未登记任何接口权限: clientId=" + clientId);
        }
        for (String prefix : allowed) {
            if (requestPath != null && requestPath.startsWith(prefix)) {
                return;
            }
        }
        throw new ViamServiceException(ViamErrorCode.SERVICE_IDENTITY_PERMISSION_DENIED,
                "调用方无权访问: clientId=" + clientId + ", path=" + requestPath);
    }
}
