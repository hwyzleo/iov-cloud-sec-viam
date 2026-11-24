package net.hwyz.iov.cloud.sec.viam.service.application.service;

import net.hwyz.iov.cloud.edd.vmd.api.vo.response.VehiclePartBindingExResponse;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.PrincipalAssetMapping;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SecurityOperationAudit;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SecurityPrincipal;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.PrincipalAssetMappingRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.SecurityOperationAuditRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * 绑定快照收敛写入器单元测试（SEC-VIAM-DSN-CR-006 / D-VIAM-032）
 *
 * @author hwyz_leo
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class BindingFactSnapshotApplierTest {

    @Mock
    private SecurityPrincipalAppService securityPrincipalAppService;

    @Mock
    private PrincipalAssetMappingRepository mappingRepository;

    @Mock
    private SecurityOperationAuditRepository auditRepository;

    @InjectMocks
    private BindingFactSnapshotApplier applier;

    private static final Instant BIND_TIME = Instant.parse("2026-09-23T03:39:54Z");

    private static SecurityPrincipal principal(String id) {
        return SecurityPrincipal.builder().principalId(id).hsmUid("u").build();
    }

    private static VehiclePartBindingExResponse binding(long bindingId, String sn, String category, String chipUid) {
        return VehiclePartBindingExResponse.builder()
                .bindingId(bindingId).vin("VIN1").partCode("PC").sn(sn)
                .deviceCategory(category).chipUid(chipUid).bindTime(BIND_TIME).build();
    }

    private static PrincipalAssetMapping mapping(long bindingId, String sn, String category, String principalId) {
        return PrincipalAssetMapping.builder()
                .principalId(principalId).vin("VIN1").deviceSn(sn).bindingId(bindingId)
                .bindingVersion(bindingId).bindingUpdatedAt(BIND_TIME)
                .deviceCategory(category).state(PrincipalAssetMapping.MappingState.ACTIVE)
                .build();
    }

    @Test
    @DisplayName("首次绑定：登记主体并新建 ACTIVE 映射")
    void apply_shouldCreateActiveMapping() {
        when(securityPrincipalAppService.registerPrincipal(anyString(), anyString(), anyString()))
                .thenReturn(principal("P1"));
        when(mappingRepository.listActiveByVin("VIN1")).thenReturn(List.of());

        BindingFactSnapshotApplier.Outcome outcome = applier.apply("VIN1", "evt-1",
                List.of(binding(2L, "SN-IVI", "IVI", "uid-ivi")), Set.of("SN-IVI"), "VMD_FACT");

        assertEquals(1, outcome.getCreated());
        ArgumentCaptor<PrincipalAssetMapping> captor = ArgumentCaptor.forClass(PrincipalAssetMapping.class);
        verify(mappingRepository).save(captor.capture());
        PrincipalAssetMapping saved = captor.getValue();
        assertEquals("P1", saved.getPrincipalId());
        assertEquals(2L, saved.getBindingId());
        assertEquals(2L, saved.getBindingVersion());
        assertEquals("IVI", saved.getDeviceCategory());
        assertEquals(PrincipalAssetMapping.MappingState.ACTIVE, saved.getState());
        verify(auditRepository).save(any(SecurityOperationAudit.class));
    }

    @Test
    @DisplayName("已一致：不改写、不落库")
    void apply_shouldBeNoopWhenSnapshotUnchanged() {
        when(securityPrincipalAppService.registerPrincipal(anyString(), anyString(), anyString()))
                .thenReturn(principal("P1"));
        when(mappingRepository.listActiveByVin("VIN1"))
                .thenReturn(List.of(mapping(2L, "SN-IVI", "IVI", "P1")));

        BindingFactSnapshotApplier.Outcome outcome = applier.apply("VIN1", "evt-1",
                List.of(binding(2L, "SN-IVI", "IVI", "uid-ivi")), Set.of("SN-IVI"), "VMD_FACT");

        assertEquals(0, outcome.getCreated());
        assertEquals(1, outcome.getUnchanged());
        verify(mappingRepository, never()).save(any());
    }

    @Test
    @DisplayName("类别/版本变化：同步投影")
    void apply_shouldSyncProjectionWhenChanged() {
        when(securityPrincipalAppService.registerPrincipal(anyString(), anyString(), anyString()))
                .thenReturn(principal("P1"));
        PrincipalAssetMapping existing = mapping(2L, "SN-IVI", "DCU", "P1");
        when(mappingRepository.listActiveByVin("VIN1")).thenReturn(List.of(existing));

        BindingFactSnapshotApplier.Outcome outcome = applier.apply("VIN1", "evt-1",
                List.of(binding(2L, "SN-IVI", "IVI", "uid-ivi")), Set.of("SN-IVI"), "VMD_FACT");

        assertEquals(1, outcome.getSynced());
        assertEquals("IVI", existing.getDeviceCategory());
        assertEquals(PrincipalAssetMapping.MappingState.ACTIVE, existing.getState());
        verify(mappingRepository).save(existing);
    }

    @Test
    @DisplayName("同 SN 换绑：旧映射 SUPERSEDED，新建 ACTIVE")
    void apply_shouldSupersedeWhenSameSnNewBinding() {
        when(securityPrincipalAppService.registerPrincipal(anyString(), anyString(), anyString()))
                .thenReturn(principal("P1"));
        PrincipalAssetMapping old = mapping(1L, "SN-IVI", "IVI", "P1");
        when(mappingRepository.listActiveByVin("VIN1")).thenReturn(List.of(old));

        BindingFactSnapshotApplier.Outcome outcome = applier.apply("VIN1", "evt-1",
                List.of(binding(2L, "SN-IVI", "IVI", "uid-ivi")), Set.of("SN-IVI"), "VMD_FACT");

        assertEquals(1, outcome.getSuperseded());
        assertEquals(1, outcome.getCreated());
        assertEquals(PrincipalAssetMapping.MappingState.SUPERSEDED, old.getState());
        verify(mappingRepository, atLeast(2)).save(any());
    }

    @Test
    @DisplayName("换件（同 VIN 同类别不同 SN）：旧件映射 SUPERSEDED")
    void apply_shouldSupersedeOtherSnSameCategory() {
        when(securityPrincipalAppService.registerPrincipal(anyString(), anyString(), anyString()))
                .thenReturn(principal("P2"));
        PrincipalAssetMapping old = mapping(1L, "SN-OLD", "IVI", "P1");
        when(mappingRepository.listActiveByVin("VIN1")).thenReturn(List.of(old));

        BindingFactSnapshotApplier.Outcome outcome = applier.apply("VIN1", "evt-1",
                List.of(binding(2L, "SN-NEW", "IVI", "uid-new")), Set.of("SN-NEW"), "VMD_FACT");

        assertEquals(1, outcome.getSuperseded());
        assertEquals(1, outcome.getCreated());
        assertEquals(PrincipalAssetMapping.MappingState.SUPERSEDED, old.getState());
    }

    @Test
    @DisplayName("解绑：快照中不存在 → UNBOUND（不吊销、不触发访问失效）")
    void apply_shouldUnbindWhenAbsentFromSnapshot() {
        when(securityPrincipalAppService.registerPrincipal(anyString(), anyString(), anyString()))
                .thenReturn(principal("P1"));
        PrincipalAssetMapping gone = mapping(1L, "SN-GONE", "IVI", "P1");
        when(mappingRepository.listActiveByVin("VIN1")).thenReturn(List.of(gone));

        BindingFactSnapshotApplier.Outcome outcome = applier.apply("VIN1", "evt-unbind",
                List.of(), Set.of(), "VMD_FACT");

        assertEquals(1, outcome.getUnbound());
        assertEquals(PrincipalAssetMapping.MappingState.UNBOUND, gone.getState());
        verify(mappingRepository).save(gone);
    }

    @Test
    @DisplayName("被跳过（UID 缺失）的 SN 仍在快照内：不得误判解绑")
    void apply_shouldNotUnbindSkippedSn() {
        PrincipalAssetMapping skipped = mapping(1L, "SN-NO-UID", "IVI", "P1");
        when(mappingRepository.listActiveByVin("VIN1")).thenReturn(List.of(skipped));

        BindingFactSnapshotApplier.Outcome outcome = applier.apply("VIN1", "evt-1",
                List.of(), Set.of("SN-NO-UID"), "VMD_FACT");

        assertEquals(0, outcome.getUnbound());
        assertEquals(PrincipalAssetMapping.MappingState.ACTIVE, skipped.getState());
        verify(mappingRepository, never()).save(any());
    }

    @Test
    @DisplayName("审计写入失败不影响收敛结果")
    void apply_shouldTolerateAuditFailure() {
        when(securityPrincipalAppService.registerPrincipal(anyString(), anyString(), anyString()))
                .thenReturn(principal("P1"));
        when(mappingRepository.listActiveByVin("VIN1")).thenReturn(List.of());
        doThrow(new IllegalStateException("audit down")).when(auditRepository).save(any());

        BindingFactSnapshotApplier.Outcome outcome = applier.apply("VIN1", "evt-1",
                List.of(binding(2L, "SN-IVI", "IVI", "uid-ivi")), Set.of("SN-IVI"), "VMD_FACT");

        assertEquals(1, outcome.getCreated());
        verify(mappingRepository).save(any());
    }

    @Test
    @DisplayName("复用主体：已有主体不重复登记")
    void apply_shouldReusePrincipal() {
        when(securityPrincipalAppService.registerPrincipal(anyString(), anyString(), anyString()))
                .thenReturn(principal("P-EXIST"));
        when(mappingRepository.listActiveByVin("VIN1")).thenReturn(List.of());

        applier.apply("VIN1", "evt-1",
                List.of(binding(2L, "SN-IVI", "IVI", "uid-ivi")), Set.of("SN-IVI"), "VMD_FACT");

        verify(securityPrincipalAppService).registerPrincipal(eq("uid-ivi"), eq("VMD_FACT"), eq("2"));
    }
}
