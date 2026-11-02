package net.hwyz.iov.cloud.sec.viam.service.adapter.web.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.framework.common.bean.ApiResponse;
import net.hwyz.iov.cloud.framework.common.constant.CustomHeaders;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.nio.charset.StandardCharsets;

/**
 * 服务身份映射拦截器（SEC-VIAM-DSN-CR-001 / R1，G-4 平台内网信任链）。
 * <p>
 * 对 {@code /api/service/**} 全部端点强制 {@code X-Client-Id} 身份映射与接口授权：
 * <ul>
 *   <li>缺失/空/多值歧义 → 403（SERVICE_IDENTITY_MISSING）；</li>
 *   <li>未登记 clientId → 403（SERVICE_IDENTITY_FORBIDDEN）；</li>
 *   <li>已登记但路径越权 → 403（SERVICE_IDENTITY_PERMISSION_DENIED）；</li>
 *   <li>通过后以 {@link WorkloadContextHolder} 承载身份供审计（非请求体自报）。</li>
 * </ul>
 * 身份来源为平台受控内网中的服务身份约定（X-Client-Id 由调用方受控注入），
 * 不宣称逐请求密码学验证；外部伪造由网关边界与受限网络可达性负责（见 CR-001 R1.2）。
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
    private final ServiceAccessPolicy accessPolicy;
    private final ObjectMapper objectMapper;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        String path = request.getRequestURI();
        if (!path.startsWith(SERVICE_API_ROOT)) {
            return true;
        }
        for (String prefix : properties.getUnauthenticatedPrefixes()) {
            if (path.startsWith(prefix)) {
                return true;
            }
        }
        try {
            String resolved = resolveClientId(request);
            if (resolved == null) {
                throw new ViamServiceException(ViamErrorCode.SERVICE_IDENTITY_FORBIDDEN,
                        "服务身份缺失、未知或歧义，拒绝访问");
            }
            accessPolicy.requireAccess(resolved, path);
            WorkloadContextHolder.set(buildContext(request, path));
            return true;
        } catch (ViamServiceException e) {
            log.warn("服务身份映射/授权失败: path={}, code={}, reason={}", path, e.getCode(), e.getMessage());
            writeError(response, e.getCode(), e.getMessage());
            return false;
        } catch (Exception e) {
            log.warn("服务身份映射异常: path={}, err={}", path, e.getMessage());
            writeError(response, ViamErrorCode.SERVICE_IDENTITY_FORBIDDEN.getCode(), "服务身份映射异常，拒绝访问");
            return false;
        }
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler,
                                Exception ex) {
        WorkloadContextHolder.clear();
    }

    /**
     * 解析请求携带的服务身份（包内可见，供测试）。单一明确值；空/多值歧义 → null。
     */
    String resolveClientId(HttpServletRequest request) {
        return accessPolicy.resolveClientId(singleHeader(request, CustomHeaders.CLIENT_ID));
    }

    /**
     * 构建 workload 上下文（包内可见，供测试）。
     */
    WorkloadContext buildContext(HttpServletRequest request, String path) {
        String clientId = accessPolicy.resolveClientId(singleHeader(request, CustomHeaders.CLIENT_ID));
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

    private void writeError(HttpServletResponse response, String code, String message) throws java.io.IOException {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        ApiResponse<Void> body = ApiResponse.<Void>builder()
                .code(code)
                .message(message)
                .timestamp(System.currentTimeMillis())
                .build();
        response.getWriter().write(objectMapper.writeValueAsString(body));
    }
}
