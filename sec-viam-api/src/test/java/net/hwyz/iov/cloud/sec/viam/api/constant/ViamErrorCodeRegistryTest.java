package net.hwyz.iov.cloud.sec.viam.api.constant;

import net.hwyz.iov.cloud.framework.common.exception.HttpStatusAware;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 错误码注册表治理测试（SEC-VIAM-DSN-CR-005）。
 * <p>
 * 静态初始化即 fail-fast 校验码段格式、唯一性与旧码映射目标存在性；
 * 本测试同时锁定“错误码 → 机器面 HTTP 状态”的声明能力。
 * </p>
 *
 * @author hwyz_leo
 */
@DisplayName("VIAM 错误码注册表治理")
class ViamErrorCodeRegistryTest {

    private static final Pattern CODE_PATTERN = Pattern.compile("^702\\d{3}$");

    @Test
    @DisplayName("全部错误码匹配 702xxx 且无重复登记")
    void allCodesRegisteredOnce() {
        assertEquals(ViamErrorCode.values().length, ViamErrorCodeRegistry.codes().size());
        for (ViamErrorCode errorCode : ViamErrorCode.values()) {
            assertTrue(CODE_PATTERN.matcher(errorCode.getCode()).matches(),
                    "错误码格式非法: " + errorCode.name() + "=" + errorCode.getCode());
            assertSame(errorCode, ViamErrorCodeRegistry.of(errorCode.getCode()));
        }
    }

    @Test
    @DisplayName("旧码映射目标必须已登记（702xxx）")
    void legacyMappingTargetsRegistered() {
        assertFalse(ViamLegacyCodeMapping.entries().isEmpty());
        ViamLegacyCodeMapping.entries().forEach((legacyCode, newCode) ->
                assertTrue(ViamErrorCodeRegistry.find(newCode).isPresent(),
                        "旧码映射目标未登记: " + legacyCode + " -> " + newCode));
    }

    @Test
    @DisplayName("未登记错误码查询失败，不伪造错误码")
    void unregisteredCodeRejected() {
        assertFalse(ViamErrorCodeRegistry.find("999999").isPresent());
        assertFalse(ViamErrorCodeRegistry.find(null).isPresent());
        assertThrows(IllegalArgumentException.class, () -> ViamErrorCodeRegistry.of("999999"));
    }

    @Test
    @DisplayName("机器面默认状态 422；设备证明参数非法声明 400")
    void httpStatusHints() {
        assertEquals(HttpStatusAware.DEFAULT_BUSINESS_ERROR_STATUS,
                ViamErrorCode.CERTIFICATE_DEVICE_NOT_BOUND.getHttpStatus());
        assertEquals(400, ViamErrorCode.PROOF_VERIFY_PARAM_INVALID.getHttpStatus());
    }
}
