package net.hwyz.iov.cloud.sec.viam.service.adapter.web.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.framework.common.bean.ApiResponse;
import net.hwyz.iov.cloud.sec.viam.api.security.ViamServiceAuthHeaders;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.nio.charset.StandardCharsets;

/**
 * 服务身份认证拦截器（G-4）。
 * <p>
 * 对 {@code /api/service/**} 全部端点强制验签 + 接口授权；验签失败返回 403（fail-closed）。
 * 认证成功后以 {@link WorkloadContextHolder} 承载身份供审计使用；
 * 无任何"dev 自动信任 VAGW"运行旁路。
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
    private final ServiceIdentityVerifier verifier;
    private final ServiceAccessPolicy accessPolicy;
    private final ObjectMapper objectMapper;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        String path = request.getRequestURI();
        if (!path.startsWith(SERVICE_API_ROOT)) {
            return true;
        }
        // 显式豁免前缀（仅健康/只读；默认为空，禁止包含 /api/service/** 安全写入）
        for (String prefix : properties.getUnauthenticatedPrefixes()) {
            if (path.startsWith(prefix)) {
                return true;
            }
        }
        try {
            CachedBodyHttpServletRequest cached = new CachedBodyHttpServletRequest(request);
            WorkloadContext context = verifier.verify(cached, cached.getBody());
            accessPolicy.requireAccess(context.clientId(), path);
            WorkloadContextHolder.set(context);
            return true;
        } catch (ViamServiceException e) {
            log.warn("服务身份认证失败: path={}, code={}, reason={}", path, e.getCode(), e.getMessage());
            writeError(response, e.getCode(), e.getMessage());
            return false;
        } catch (Exception e) {
            log.warn("服务身份认证异常: path={}, err={}", path, e.getMessage());
            writeError(response, "702701", "服务身份认证异常，拒绝访问");
            return false;
        }
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler,
                                Exception ex) {
        WorkloadContextHolder.clear();
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
