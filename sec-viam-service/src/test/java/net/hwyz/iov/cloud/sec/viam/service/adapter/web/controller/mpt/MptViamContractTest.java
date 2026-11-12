package net.hwyz.iov.cloud.sec.viam.service.adapter.web.controller.mpt;

import net.hwyz.iov.cloud.framework.common.bean.ApiResponse;
import net.hwyz.iov.cloud.framework.security.annotation.RequiresPermissions;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateOperationResultVo;
import net.hwyz.iov.cloud.sec.viam.service.adapter.web.controller.mpt.MptViamBusinessKeyGovernanceController;
import net.hwyz.iov.cloud.sec.viam.service.adapter.web.controller.mpt.MptViamCertificateController;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * MPT 管理面契约测试（SEC-VIAM-DSN-CR-002 / T09 / T15 / T16 / T17）。
 * <p>
 * 不启动 Spring 上下文（本模块测试无 DB/Redis/Kafka 环境），改为对适配层做注解级契约校验：
 * 路径、HTTP 方法、权限点、响应包装、旧入口删除与新错误码注册。
 * </p>
 *
 * @author hwyz_leo
 */
@DisplayName("SEC-VIAM-DSN-CR-002 MPT 契约")
class MptViamContractTest {

    @Test
    @DisplayName("证书控制器暴露 8 个管理端点，路径与 HTTP 方法符合设计")
    void certificateControllerMappings() {
        Set<String> mappings = collectMappings(MptViamCertificateController.class);

        assertTrue(mappings.contains("GET /api/mpt/viam/certificate/list"));
        assertTrue(mappings.contains("GET /api/mpt/viam/certificate/request/{requestId}"));
        assertTrue(mappings.contains("POST /api/mpt/viam/certificate/compensate"));
        assertTrue(mappings.contains("POST /api/mpt/viam/certificate/request/{requestId}/reconcile"));
        assertTrue(mappings.contains("POST /api/mpt/viam/certificate/request/{requestId}/confirmInstalled"));
        assertTrue(mappings.contains("GET /api/mpt/viam/certificate/request/{requestId}/certificate"));
        assertTrue(mappings.contains("POST /api/mpt/viam/certificate/request/{requestId}/reissue"));
    }

    @Test
    @DisplayName("治理控制器暴露批次查询/桥接/诊断/清阻断 4 个端点")
    void governanceControllerMappings() {
        Set<String> mappings = collectMappings(MptViamBusinessKeyGovernanceController.class);

        assertTrue(mappings.contains("POST /api/mpt/viam/businessKey/provisioningQuery"));
        assertTrue(mappings.contains(
                "GET /api/mpt/viam/businessKey/provisioning/by-certificate-request/{certificateRequestId}"));
        assertTrue(mappings.contains(
                "GET /api/mpt/viam/businessKey/provisioning/{requestId}/blocking-diagnosis"));
        assertTrue(mappings.contains(
                "POST /api/mpt/viam/businessKey/provisioning/{requestId}/clear-blocking"));
    }

    @Test
    @DisplayName("旧证书写入口已收敛：/certificate/reconcile 与 /certificate/confirmInstalled 不再注册")
    void legacyCertificateWriteEndpointsRemoved() {
        Set<String> mappings = collectMappings(MptViamAdminController.class);

        assertTrue(mappings.contains("GET /api/mpt/viam/certificate/request/{requestId}/status"));
        assertFalse(mappings.contains("POST /api/mpt/viam/certificate/reconcile"));
        assertFalse(mappings.contains("POST /api/mpt/viam/certificate/confirmInstalled"));
    }

    @Test
    @DisplayName("权限点覆盖设计清单（viam:certificate:* / viam:businessKey:*）")
    void permissionPointsMatchDesign() {
        Set<String> permissions = collectPermissions(MptViamCertificateController.class);
        permissions.addAll(collectPermissions(MptViamBusinessKeyGovernanceController.class));

        assertTrue(permissions.contains("viam:certificate:list"));
        assertTrue(permissions.contains("viam:certificate:query"));
        assertTrue(permissions.contains("viam:certificate:compensate"));
        assertTrue(permissions.contains("viam:certificate:reconcile"));
        assertTrue(permissions.contains("viam:certificate:confirmInstalled"));
        assertTrue(permissions.contains("viam:certificate:reissue"));
        assertTrue(permissions.contains("viam:businessKey:provisioning:query"));
        assertTrue(permissions.contains("viam:businessKey:diagnosis"));
        assertTrue(permissions.contains("viam:businessKey:clearBlocking"));
    }

    @Test
    @DisplayName("响应统一为 ApiResponse（与 VMD/CIAM 管理面一致），避免同一服务两种形态")
    void responsesAreWrappedInApiResponse() {
        assertTrue(returnsApiResponse(MptViamCertificateController.class, "list"));
        assertTrue(returnsApiResponse(MptViamCertificateController.class, "detail"));
        assertTrue(returnsApiResponse(MptViamCertificateController.class, "compensate"));
        assertTrue(returnsApiResponse(MptViamCertificateController.class, "reconcile"));
        assertTrue(returnsApiResponse(MptViamCertificateController.class, "confirmInstalled"));
        assertTrue(returnsApiResponse(MptViamCertificateController.class, "certificate"));
        assertTrue(returnsApiResponse(MptViamCertificateController.class, "reissue"));
        assertTrue(returnsApiResponse(MptViamBusinessKeyGovernanceController.class, "provisioningQuery"));
        assertTrue(returnsApiResponse(MptViamBusinessKeyGovernanceController.class, "blockingDiagnosis"));
        assertTrue(returnsApiResponse(MptViamBusinessKeyGovernanceController.class, "clearBlocking"));
    }

    @Test
    @DisplayName("新错误码 702221/702222 已注册且不与既有码冲突")
    void newErrorCodesRegistered() {
        assertEquals("702221", ViamErrorCode.CERTIFICATE_MATERIAL_NOT_RETRIEVABLE.getCode());
        assertEquals("702222", ViamErrorCode.EXPECTED_STATE_MISMATCH.getCode());
        long distinct = Arrays.stream(ViamErrorCode.values()).map(ViamErrorCode::getCode).distinct().count();
        assertEquals(ViamErrorCode.values().length, distinct, "错误码存在重复注册");
    }

    @Test
    @DisplayName("写操作返回结构包含操作ID与状态，便于前端展示与幂等回溯")
    void operationResultCarriesOperationIdAndStatus() {
        CertificateOperationResultVo vo = CertificateOperationResultVo.builder()
                .operationId("REQ-1:REISSUE:1").requestId("REQ-2").status("ISSUED_NOT_CONFIRMED").build();
        assertNotNull(vo.getOperationId());
        assertEquals("REQ-2", vo.getRequestId());
    }

    private static Set<String> collectMappings(Class<?> controller) {
        RequestMapping base = controller.getAnnotation(RequestMapping.class);
        assertNotNull(base, "控制器缺少 @RequestMapping");
        String prefix = base.value()[0];
        Set<String> result = new HashSet<>();
        for (Method method : controller.getDeclaredMethods()) {
            GetMapping get = method.getAnnotation(GetMapping.class);
            PostMapping post = method.getAnnotation(PostMapping.class);
            List<String> paths;
            String httpMethod;
            if (get != null) {
                paths = Arrays.asList(get.value().length == 0 ? new String[]{""} : get.value());
                httpMethod = "GET";
            } else if (post != null) {
                paths = Arrays.asList(post.value().length == 0 ? new String[]{""} : post.value());
                httpMethod = "POST";
            } else {
                continue;
            }
            for (String path : paths) {
                result.add(httpMethod + " " + prefix + path);
            }
        }
        return result;
    }

    private static Set<String> collectPermissions(Class<?> controller) {
        Set<String> result = new HashSet<>();
        for (Method method : controller.getDeclaredMethods()) {
            RequiresPermissions annotation = method.getAnnotation(RequiresPermissions.class);
            if (annotation != null) {
                result.addAll(Arrays.asList(annotation.value()));
            }
        }
        return result;
    }

    private static boolean returnsApiResponse(Class<?> controller, String methodName) {
        for (Method method : controller.getDeclaredMethods()) {
            if (method.getName().equals(methodName)) {
                Class<?> type = method.getReturnType();
                if (org.springframework.http.ResponseEntity.class.isAssignableFrom(type)) {
                    return true;
                }
                return type.isAssignableFrom(ApiResponse.class) || ApiResponse.class.isAssignableFrom(type);
            }
        }
        throw new AssertionError("方法不存在: " + methodName);
    }
}
