package net.hwyz.iov.cloud.sec.viam.service.adapter.web.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * 内网互信语义测试（SEC-VIAM-DSN-CR-001 追加修订 R2）：
 * /api/service/** 不做身份映射/授权强制，缺失/未知 X-Client-Id 一律放行，仅记录供审计。
 */
class ServiceIdentityInterceptorTest {

    private ServiceIdentityProperties properties;
    private ServiceIdentityInterceptor interceptor;

    @BeforeEach
    void setUp() {
        properties = new ServiceIdentityProperties();
        properties.setAccess(Map.of("VAGW", List.of("/api/service/")));
        properties.setUnauthenticatedPrefixes(List.of("/api/service/health"));
        interceptor = new ServiceIdentityInterceptor(properties);
        WorkloadContextHolder.clear();
    }

    @AfterEach
    void tearDown() {
        WorkloadContextHolder.clear();
    }

    private HttpServletRequest request(String uri, String clientId) {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getRequestURI()).thenReturn(uri);
        if (clientId == null) {
            when(req.getHeaders("X-Client-Id")).thenReturn(Collections.emptyEnumeration());
        } else {
            when(req.getHeaders("X-Client-Id")).thenReturn(Collections.enumeration(List.of(clientId)));
        }
        return req;
    }

    @Test
    void missingClientIdStillPassesThrough() throws Exception {
        HttpServletRequest req = request("/api/service/deviceLogin/v1/onboarding/PR-1", null);
        assertTrue(interceptor.preHandle(req, mock(HttpServletResponse.class), new Object()));
        WorkloadContext ctx = WorkloadContextHolder.get();
        assertNotNull(ctx, "缺失 X-Client-Id 也必须承载审计上下文");
        assertNull(ctx.clientId());
    }

    @Test
    void unknownClientIdStillPassesThroughAndIsRecorded() throws Exception {
        HttpServletRequest req = request("/api/service/deviceLogin/v1/onboarding/PR-1", "OAPI");
        assertTrue(interceptor.preHandle(req, mock(HttpServletResponse.class), new Object()));
        assertEquals("OAPI", WorkloadContextHolder.get().clientId());
    }

    @Test
    void registeredClientIdRecorded() throws Exception {
        HttpServletRequest req = request("/api/service/deviceLogin/v1/onboarding/PR-1", "VAGW");
        assertTrue(interceptor.preHandle(req, mock(HttpServletResponse.class), new Object()));
        assertEquals("VAGW", WorkloadContextHolder.get().clientId());
    }

    @Test
    void nonServicePathSkipped() throws Exception {
        HttpServletRequest req = request("/api/admin/login", null);
        assertTrue(interceptor.preHandle(req, mock(HttpServletResponse.class), new Object()));
        assertNull(WorkloadContextHolder.get());
    }

    @Test
    void unauthenticatedPrefixSkipped() throws Exception {
        HttpServletRequest req = request("/api/service/health", null);
        assertTrue(interceptor.preHandle(req, mock(HttpServletResponse.class), new Object()));
        assertNull(WorkloadContextHolder.get());
    }

    @Test
    void afterCompletionClearsContext() throws Exception {
        HttpServletRequest req = request("/api/service/deviceLogin/v1/onboarding/PR-1", "VAGW");
        interceptor.preHandle(req, mock(HttpServletResponse.class), new Object());
        assertNotNull(WorkloadContextHolder.get());
        interceptor.afterCompletion(req, mock(HttpServletResponse.class), new Object(), null);
        assertNull(WorkloadContextHolder.get());
    }
}
