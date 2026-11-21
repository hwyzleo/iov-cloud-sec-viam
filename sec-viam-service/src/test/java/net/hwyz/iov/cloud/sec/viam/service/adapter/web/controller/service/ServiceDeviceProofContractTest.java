package net.hwyz.iov.cloud.sec.viam.service.adapter.web.controller.service;

import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamServiceConstants;
import net.hwyz.iov.cloud.sec.viam.api.fallback.ViamDeviceProofServiceFallbackFactory;
import net.hwyz.iov.cloud.sec.viam.api.service.ViamDeviceProofService;
import net.hwyz.iov.cloud.sec.viam.api.vo.DeviceProofVerifyRequestVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.DeviceProofVerifyResultVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.enums.DeviceProofReasonCode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 设备证明校验契约测试（SEC-VIAM-DSN-CR-003 / §13.3 / §13.5）。
 * <p>
 * 不启动 Spring 上下文：对适配层做注解级契约校验——路径、HTTP 方法、Feign 契约、
 * 错误码注册与降级 fail-closed 语义。
 * </p>
 *
 * @author hwyz_leo
 */
@DisplayName("SEC-VIAM-DSN-CR-003 设备证明校验契约")
class ServiceDeviceProofContractTest {

    @Test
    @DisplayName("控制器路径与 HTTP 方法符合设计：POST /api/service/deviceProof/v1/verify")
    void controllerMapping() {
        RequestMapping classMapping = ServiceDeviceProofController.class.getAnnotation(RequestMapping.class);
        assertNotNull(classMapping);
        assertTrue(classMapping.value()[0].endsWith("/deviceProof/v1"));

        Set<String> mappings = new HashSet<>();
        for (Method method : ServiceDeviceProofController.class.getDeclaredMethods()) {
            PostMapping post = method.getAnnotation(PostMapping.class);
            if (post != null) {
                Arrays.stream(post.value()).forEach(path -> mappings.add("POST " + path));
            }
        }
        assertTrue(mappings.contains("POST /verify"));
    }

    @Test
    @DisplayName("Feign 契约与控制器实现同一接口，路径常量唯一源")
    void feignContract() {
        assertTrue(ViamDeviceProofService.class.isAssignableFrom(ServiceDeviceProofController.class));
        assertEquals("/api/service" + "/deviceProof/v1", ViamServiceConstants.DEVICE_PROOF_V1);
    }

    @Test
    @DisplayName("降级工厂 fail-closed：valid=false + DEPENDENCY_UNAVAILABLE")
    void fallbackFailClosed() {
        ViamDeviceProofService fallback = new ViamDeviceProofServiceFallbackFactory()
                .create(new IllegalStateException("down"));

        DeviceProofVerifyResultVo result = fallback.verify(DeviceProofVerifyRequestVo.builder()
                .proofType("MTLS_CERT").proof("AQID").nonce("nonce-0123456789abcdef").build());

        assertFalse(result.isValid());
        assertEquals(DeviceProofReasonCode.DEPENDENCY_UNAVAILABLE.name(), result.getReasonCode());
        assertNotNull(result.getVerifiedAt());
    }

    @Test
    @DisplayName("错误码 702720～702725 已注册且在 7027xx 段")
    void errorCodesRegistered() {
        assertEquals("702720", ViamErrorCode.PROOF_VERIFY_PARAM_INVALID.getCode());
        assertEquals("702721", ViamErrorCode.PROOF_INVALID.getCode());
        assertEquals("702722", ViamErrorCode.PROOF_NONCE_REPLAYED.getCode());
        assertEquals("702723", ViamErrorCode.PROOF_SUBJECT_UNAVAILABLE.getCode());
        assertEquals("702724", ViamErrorCode.PROOF_DEPENDENCY_UNAVAILABLE.getCode());
        assertEquals("702725", ViamErrorCode.PROOF_RATE_LIMITED.getCode());
        for (ViamErrorCode code : ViamErrorCode.values()) {
            assertTrue(code.getCode().startsWith("702"));
        }
    }

    @Test
    @DisplayName("请求 VO 强制 proofType/proof/nonce 必填，deviceId 可选")
    void requestValidationDeclared() throws NoSuchFieldException {
        assertNotNull(DeviceProofVerifyRequestVo.class.getDeclaredField("proofType")
                .getAnnotation(jakarta.validation.constraints.NotBlank.class));
        assertNotNull(DeviceProofVerifyRequestVo.class.getDeclaredField("proof")
                .getAnnotation(jakarta.validation.constraints.NotBlank.class));
        assertNotNull(DeviceProofVerifyRequestVo.class.getDeclaredField("nonce")
                .getAnnotation(jakarta.validation.constraints.NotBlank.class));
        assertTrue(DeviceProofVerifyRequestVo.class.getDeclaredField("deviceId")
                .getAnnotation(jakarta.validation.constraints.NotBlank.class) == null);
    }
}
