package net.hwyz.iov.cloud.sec.viam.service.adapter.web.security;

import jakarta.servlet.http.HttpServletRequest;
import net.hwyz.iov.cloud.framework.common.constant.CustomHeaders;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 服务调用方登记与授权策略测试（SEC-VIAM-DSN-CR-001 / R1，内网互信修订 R2）
 * <p>
 * 保留 clientId→路径前缀登记矩阵：登记识别、越权拒绝仍由 {@link ServiceAccessPolicy} 提供；
 * 拦截器不再强制调用（内网互信），登记缺失/未知不再导致请求 403。
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
        assertNull(policy.resolveClientId("ATTACKER")); // 未登记：登记仅供审计识别，不再拒绝请求
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
}
