package net.hwyz.iov.cloud.sec.viam.service.adapter.web.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.framework.common.constant.CustomHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * 服务身份审计拦截器（内网互信）。
 * <p>
 * 对 {@code /api/service/**} 端点不再强制 {@code X-Client-Id} 身份映射与接口授权
 * （内网服务间互信，见 SEC-VIAM-DSN-CR-001 追加修订 R2）；请求一律放行，不返回 403。
 * 仅承载调用方自报的 {@code X-Client-Id} 供审计（{@link WorkloadContextHolder}），
 * 缺失/未知/未登记均不拒绝。审计 caller 取自本上下文，不取请求体自报。
 * 调用方真实身份的边界保证由平台受限内网可达性与外部网关负责（CR-001 R1.2）。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ServiceIdentityInterceptor implements HandlerInterceptor {

    private static final String SERVICE_API_ROOT = ServiceAccessPolicy.SERVICE_API_ROOT;

    private final ServiceIdentityProperties properties;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        String path = request.getRequestURI();
        if (!path.startsWith(SERVICE_API_ROOT)) {
            return true;
        }
        for (String prefix : properties.getUnauthenticatedPrefixes()) {
            if (path.startsWith(prefix)) {
                return true;
            }
        }
        // 内网互信：不做身份映射/授权强制，仅记录调用方自报 X-Client-Id 供审计
        WorkloadContextHolder.set(buildContext(request, path));
        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler,
                                Exception ex) {
        WorkloadContextHolder.clear();
    }

    /**
     * 构建 workload 上下文（包内可见，供测试）。X-Client-Id 缺失/未知不拒绝，原样记录。
     */
    WorkloadContext buildContext(HttpServletRequest request, String path) {
        String clientId = singleHeader(request, CustomHeaders.CLIENT_ID);
        return new WorkloadContext(clientId, path);
    }

    private static String singleHeader(HttpServletRequest request, String name) {
        var values = request.getHeaders(name);
        if (values == null) {
            return null;
        }
        java.util.List<String> list = java.util.Collections.list(values);
        if (list.size() != 1) {
            return null; // 缺失或多值歧义
        }
        String value = list.get(0);
        return value == null ? null : value.trim();
    }
}
