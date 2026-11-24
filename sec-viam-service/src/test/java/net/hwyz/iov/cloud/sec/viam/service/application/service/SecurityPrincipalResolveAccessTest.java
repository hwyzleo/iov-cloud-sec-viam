package net.hwyz.iov.cloud.sec.viam.service.application.service;

import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.PrincipalAssetMapping;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SecurityPrincipal;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.PrincipalAssetMappingRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.SecurityPrincipalRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * 车辆接入身份按 VIN 解析单元测试（SEC-VIAM-DSN-CR-006 / D-VIAM-037）
 * <p>
 * 事件驱动登记后同一 VIN 可能同时存在 TBOX 与 IVI 映射；接入身份解析必须优先 TBOX，
 * 不得因多设备共存判定为冲突（否则 VAGW 车辆接入会被误阻断）。
 * </p>
 *
 * @author hwyz_leo
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SecurityPrincipalResolveAccessTest {

    @Mock
    private PrincipalAssetMappingRepository mappingRepository;

    @Mock
    private SecurityPrincipalRepository principalRepository;

    @InjectMocks
    private SecurityPrincipalAppService appService;

    private static PrincipalAssetMapping mapping(String principalId, String sn, String category) {
        return PrincipalAssetMapping.builder()
                .principalId(principalId).vin("VIN1").deviceSn(sn).deviceCategory(category)
                .bindingId(1L).bindingVersion(1L)
                .state(PrincipalAssetMapping.MappingState.ACTIVE)
                .build();
    }

    @Test
    @DisplayName("同 VIN 同时有 TBOX 与 IVI：接入身份取 TBOX，不判冲突")
    void resolve_shouldPreferTboxWhenMultiDevice() {
        when(mappingRepository.listActiveByVin("VIN1")).thenReturn(List.of(
                mapping("P-TBOX", "SN-TBOX", "TBOX"),
                mapping("P-IVI", "SN-IVI", "IVI")));
        when(principalRepository.findByPrincipalId("P-TBOX"))
                .thenReturn(Optional.of(SecurityPrincipal.builder().principalId("P-TBOX").hsmUid("u1").build()));

        SecurityPrincipal principal = appService.resolvePrincipalByVin("VIN1");
        PrincipalAssetMapping mapping = appService.resolveAccessMappingByVin("VIN1");

        assertEquals("P-TBOX", principal.getPrincipalId());
        assertEquals("SN-TBOX", mapping.getDeviceSn());
    }

    @Test
    @DisplayName("历史单设备（仅 IVI）：唯一映射回退，保持兼容")
    void resolve_shouldFallbackWhenSingleNonTbox() {
        PrincipalAssetMapping only = mapping("P-IVI", "SN-IVI", "IVI");
        when(mappingRepository.listActiveByVin("VIN1")).thenReturn(List.of(only));
        when(principalRepository.findByPrincipalId("P-IVI"))
                .thenReturn(Optional.of(SecurityPrincipal.builder().principalId("P-IVI").hsmUid("u2").build()));

        assertEquals("P-IVI", appService.resolvePrincipalByVin("VIN1").getPrincipalId());
        assertEquals("SN-IVI", appService.resolveAccessMappingByVin("VIN1").getDeviceSn());
    }

    @Test
    @DisplayName("无 TBOX 且多设备：仍按冲突失败（fail-closed，不择一）")
    void resolve_shouldConflictWhenNoTboxAndMultiple() {
        when(mappingRepository.listActiveByVin("VIN1")).thenReturn(List.of(
                mapping("P-IVI", "SN-IVI", "IVI"),
                mapping("P-CCU", "SN-CCU", "CCU")));

        assertThrows(ViamServiceException.class, () -> appService.resolvePrincipalByVin("VIN1"));
        assertThrows(ViamServiceException.class, () -> appService.resolveAccessMappingByVin("VIN1"));
    }

    @Test
    @DisplayName("无映射：冲突失败")
    void resolve_shouldConflictWhenNoMapping() {
        when(mappingRepository.listActiveByVin("VIN1")).thenReturn(List.of());

        assertThrows(ViamServiceException.class, () -> appService.resolveAccessMappingByVin("VIN1"));
        assertThrows(ViamServiceException.class, () -> appService.resolvePrincipalByVin("VIN1"));
    }

    @Test
    @DisplayName("同 VIN 两个 TBOX：仍冲突（不猜哪个是接入设备）")
    void resolve_shouldConflictWhenTwoTbox() {
        when(mappingRepository.listActiveByVin("VIN1")).thenReturn(List.of(
                mapping("P1", "SN1", "TBOX"),
                mapping("P2", "SN2", "TBOX")));

        assertThrows(ViamServiceException.class, () -> appService.resolveAccessMappingByVin("VIN1"));
    }
}
