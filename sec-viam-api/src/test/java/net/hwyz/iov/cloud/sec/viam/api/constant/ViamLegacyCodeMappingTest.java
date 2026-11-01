package net.hwyz.iov.cloud.sec.viam.api.constant;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 错误码映射层单元测试（SEC-VIAM-DSN-CR-001 §3）
 * <p>
 * 旧 806xxx（VMD）/ 401xxx（TSP）源码错误映射到 702xxx 新码；VAGW 804xxx 不纳入。
 * </p>
 *
 * @author hwyz_leo
 */
class ViamLegacyCodeMappingTest {

    @Test
    void mapsVmdCertificateCodes() {
        assertEquals("702201", ViamLegacyCodeMapping.mapOrSelf("806040")); // CERTIFICATE_VIN_NOT_EXIST
        assertEquals("702202", ViamLegacyCodeMapping.mapOrSelf("806041")); // CERTIFICATE_DEVICE_NOT_BOUND
        assertEquals("702207", ViamLegacyCodeMapping.mapOrSelf("806046")); // CERTIFICATE_PROFILE_NOT_ALLOWED
        assertEquals("702209", ViamLegacyCodeMapping.mapOrSelf("806048")); // CERTIFICATE_ISSUANCE_UNKNOWN
    }

    @Test
    void mapsVmdKeyprovCodes() {
        assertEquals("702403", ViamLegacyCodeMapping.mapOrSelf("806083"));
        assertEquals("702405", ViamLegacyCodeMapping.mapOrSelf("806085"));
    }

    @Test
    void mapsTspAdmissionCodes() {
        assertEquals("702101", ViamLegacyCodeMapping.mapOrSelf("401001"));
        assertEquals("702102", ViamLegacyCodeMapping.mapOrSelf("401016"));
        assertEquals("702109", ViamLegacyCodeMapping.mapOrSelf("401008"));
    }

    @Test
    void keepsUnregisteredAsIs() {
        assertEquals("804001", ViamLegacyCodeMapping.mapOrSelf("804001")); // VAGW 804xxx 不纳入
        assertEquals("806999", ViamLegacyCodeMapping.mapOrSelf("806999")); // 未登记保持原码
    }

    @Test
    void newCodesAreWithin702xxxRange() {
        assertTrue(ViamErrorCode.values().length > 0);
        for (ViamErrorCode code : ViamErrorCode.values()) {
            assertTrue(code.getCode().startsWith("702"), "错误码必须为702xxx: " + code.getCode());
        }
    }
}
