package net.hwyz.iov.cloud.sec.viam.service.adapter.web.security;

import jakarta.servlet.http.HttpServletRequest;
import net.hwyz.iov.cloud.framework.common.constant.CustomHeaders;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Vector;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 服务身份映射与授权测试（SEC-VIAM-DSN-CR-001 / R1，G-4 平台内网信任链）
 * <p>
 * X-Client-Id 身份映射：缺失/空/多值歧义/未登记拒绝；已登记且路径允许放行；越权拒绝。
 * </p>
 *
 * @author hwyz_leo
 */
class ServiceAccessPolicyTest {

    private ServiceIdentityProperties properties;
    private ServiceAccessPolicy policy;

    @BeforeEach
    void setUp() {
        properties = new ServiceIdentityProperties();
        properties.setAccess(Map.of("VAGW", List.of("/api/service/")));
        policy = new ServiceAccessPolicy(properties);
    }

    @Test
    void registeredClientResolves() {
        assertEquals("VAGW", policy.resolveClientId(" VAGW "));
    }

    @Test
    void missingOrBlankOrUnknownFails() {
        assertNull(policy.resolveClientId(null));
        assertNull(policy.resolveClientId("  "));
        assertNull(policy.resolveClientId("ATTACKER")); // 未登记（内网冒充不在本层防御，但未登记身份不放行）
    }

    @Test
    void allowedPathPasses() {
        policy.requireAccess("VAGW", "/api/service/deviceAdmission/v1/decide");
        policy.requireAccess("VAGW", "/api/service/accessInvalidation/v1/receipt");
    }

    @Test
    void unauthorizedPathRejected() {
        ViamServiceException e = assertThrows(ViamServiceException.class,
                () -> policy.requireAccess("VAGW", "/api/mpt/viam/principal/block"));
        assertEquals(ViamErrorCode.SERVICE_IDENTITY_PERMISSION_DENIED.getCode(), e.getCode());
    }

    @Test
    void unregisteredClientRejected() {
        ViamServiceException e = assertThrows(ViamServiceException.class,
                () -> policy.requireAccess("OAPI_UNREGISTERED", "/api/service/deviceAdmission/v1/decide"));
        assertEquals(ViamErrorCode.SERVICE_IDENTITY_PERMISSION_DENIED.getCode(), e.getCode());
    }

    // ---- 拦截器行为（单头解析/歧义拒绝/上下文设置/清理） ----

    @Test
    void singleHeaderParsingRejectsAmbiguous() {
        ServiceIdentityInterceptor interceptor = new ServiceIdentityInterceptor(
                properties, policy, new com.fasterxml.jackson.databind.ObjectMapper());
        HttpServletRequest request = headerRequest(Map.of(
                CustomHeaders.CLIENT_ID, List.of("VAGW"),
                "X-Dummy", List.of("a", "b")));
        assertEquals("VAGW", interceptor.resolveClientId(request));
        // 多值歧义 → null
        assertNull(interceptor.resolveClientId(headerRequest(Map.of(
                CustomHeaders.CLIENT_ID, List.of("VAGW", "VAGW")))));
    }

    @Test
    void contextSetAndClearedAfterCompletion() {
        WorkloadContextHolder.clear();
        ServiceIdentityInterceptor interceptor = new ServiceIdentityInterceptor(
                properties, policy, new com.fasterxml.jackson.databind.ObjectMapper());
        HttpServletRequest request = headerRequest(Map.of(
                CustomHeaders.CLIENT_ID, List.of("VAGW"),
                "X-Dummy", List.of("a", "b")));
        WorkloadContext context = interceptor.buildContext(request,
                "/api/service/deviceAdmission/v1/decide");
        assertTrue(context.clientId().equals("VAGW"));
        WorkloadContextHolder.set(context);
        assertEquals("VAGW", WorkloadContextHolder.get().clientId());
        interceptor.afterCompletion(request, null, null, null);
        assertNull(WorkloadContextHolder.get());
    }

    private HttpServletRequest headerRequest(Map<String, List<String>> headers) {
        return new jakarta.servlet.http.HttpServletRequestWrapper(
                new org.springframework.mock.web.MockHttpServletRequest()) {
            @Override
            public java.util.Enumeration<String> getHeaders(String name) {
                List<String> values = headers.get(name);
                return values == null ? java.util.Collections.emptyEnumeration()
                        : new Vector<>(values).elements();
            }
        };
    }
}
