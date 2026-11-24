package net.hwyz.iov.cloud.sec.viam.service.application.service;

import net.hwyz.iov.cloud.edd.vmd.api.vo.response.VehiclePartBindingExResponse;
import net.hwyz.iov.cloud.sec.viam.service.adapter.kafka.BindingEnrollmentProperties;
import net.hwyz.iov.cloud.sec.viam.service.adapter.kafka.dto.VmdPartBindingChangedPayload;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.vmd.VmdBindingFactAdapter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * 绑定事实自动登记编排单元测试（SEC-VIAM-DSN-CR-006 / D-VIAM-028～034）
 *
 * @author hwyz_leo
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class BindingFactEnrollmentAppServiceTest {

    @Mock
    private VmdBindingFactAdapter vmdBindingFactAdapter;

    @Mock
    private BindingFactSnapshotApplier snapshotApplier;

    private BindingEnrollmentProperties properties;

    private BindingFactEnrollmentAppService appService;

    @BeforeEach
    void setUp() {
        properties = new BindingEnrollmentProperties();
        properties.setAllowedCategories(List.of("TBOX", "IVI"));
        properties.setMaxSnapshotBindings(4);
        appService = new BindingFactEnrollmentAppService(vmdBindingFactAdapter, snapshotApplier, properties);
        when(snapshotApplier.apply(anyString(), anyString(), anyList(), anySet(), anyString()))
                .thenReturn(new BindingFactSnapshotApplier.Outcome());
    }

    private static VmdPartBindingChangedPayload event(String vin) {
        VmdPartBindingChangedPayload payload = new VmdPartBindingChangedPayload();
        payload.setEventId("evt-1");
        payload.setVin(vin);
        payload.setBindingId(2L);
        payload.setChangeType("BIND");
        return payload;
    }

    private static VehiclePartBindingExResponse binding(String sn, String category, String chipUid) {
        return VehiclePartBindingExResponse.builder()
                .bindingId(2L)
                .vin("HWYZTEST900000001")
                .partCode("00000004AA")
                .sn(sn)
                .deviceCategory(category)
                .vehicleNodeCode("DCU_COCKPIT_SA8295P")
                .chipUid(chipUid)
                .bindTime(Instant.parse("2026-09-23T03:39:54Z"))
                .build();
    }

    @Test
    @DisplayName("白名单类别 + chipUid 可用：进入快照收敛")
    void handle_shouldEnrollWhitelistedCategory() {
        when(vmdBindingFactAdapter.listActiveBindingsByVin("HWYZTEST900000001"))
                .thenReturn(List.of(binding("00000005AA00000001", "IVI", "00000005AA0000000000000000000001")));

        BindingFactEnrollmentAppService.Result result = appService.handle(event("HWYZTEST900000001"), "t");

        assertEquals(1, result.getSnapshotSize());
        assertFalse(result.hasSkipped());
        ArgumentCaptor<List<VehiclePartBindingExResponse>> enrollable = ArgumentCaptor.forClass(List.class);
        ArgumentCaptor<Set<String>> snapshotSns = ArgumentCaptor.forClass(Set.class);
        verify(snapshotApplier).apply(eq("HWYZTEST900000001"), eq("evt-1"), enrollable.capture(),
                snapshotSns.capture(), eq("VMD_FACT"));
        assertEquals(1, enrollable.getValue().size());
        assertTrue(snapshotSns.getValue().contains("00000005AA00000001"));
    }

    @Test
    @DisplayName("非白名单类别：只记快照、不进入登记（不建主体不建映射）")
    void handle_shouldSkipNonWhitelistedCategory() {
        when(vmdBindingFactAdapter.listActiveBindingsByVin(anyString()))
                .thenReturn(List.of(binding("00000008AA00000001", "CCU", "00000008AA0000000000000000000001")));

        BindingFactEnrollmentAppService.Result result = appService.handle(event("HWYZTEST900000001"), "t");

        assertFalse(result.hasSkipped());
        ArgumentCaptor<List<VehiclePartBindingExResponse>> captor = ArgumentCaptor.forClass(List.class);
        verify(snapshotApplier).apply(anyString(), anyString(), captor.capture(), anySet(), anyString());
        assertTrue(captor.getValue().isEmpty());
    }

    @Test
    @DisplayName("白名单类别但 chipUid 缺失：单条跳过并隔离，其他条目照常收敛")
    void handle_shouldSkipOnlyMissingUidEntry() {
        when(vmdBindingFactAdapter.listActiveBindingsByVin(anyString())).thenReturn(List.of(
                binding("00000005AA00000001", "IVI", null),
                binding("00000002AA00000001", "TBOX", "00000000000000000000000000000001")));

        BindingFactEnrollmentAppService.Result result = appService.handle(event("HWYZTEST900000001"), "t");

        assertTrue(result.hasSkipped());
        assertEquals(List.of("00000005AA00000001"), result.getSkippedDeviceSns());
        ArgumentCaptor<List<VehiclePartBindingExResponse>> enrollable = ArgumentCaptor.forClass(List.class);
        ArgumentCaptor<Set<String>> snapshotSns = ArgumentCaptor.forClass(Set.class);
        verify(snapshotApplier).apply(anyString(), anyString(), enrollable.capture(), snapshotSns.capture(), anyString());
        assertEquals(1, enrollable.getValue().size());
        assertEquals("00000002AA00000001", enrollable.getValue().get(0).getSn());
        // 被跳过的 SN 仍在快照集合内，避免被误判为解绑
        assertTrue(snapshotSns.getValue().contains("00000005AA00000001"));
    }

    @Test
    @DisplayName("快照超上限：fail-closed 隔离")
    void handle_shouldFailWhenSnapshotTooLarge() {
        properties.setMaxSnapshotBindings(1);
        when(vmdBindingFactAdapter.listActiveBindingsByVin(anyString())).thenReturn(List.of(
                binding("A", "IVI", "u1"), binding("B", "IVI", "u2")));

        assertThrows(ViamServiceException.class, () -> appService.handle(event("VIN1"), "t"));
        verify(snapshotApplier, never()).apply(anyString(), anyString(), anyList(), anySet(), anyString());
    }

    @Test
    @DisplayName("VIN 缺失：拒绝处理")
    void handle_shouldRejectMissingVin() {
        assertThrows(ViamServiceException.class, () -> appService.handle(event("  "), "t"));
        verify(vmdBindingFactAdapter, never()).listActiveBindingsByVin(anyString());
    }

    @Test
    @DisplayName("登记关闭：不查快照、不写库")
    void handle_shouldSkipWhenDisabled() {
        properties.setEnabled(false);

        BindingFactEnrollmentAppService.Result result = appService.handle(event("VIN1"), "t");

        assertEquals(0, result.getSnapshotSize());
        verify(vmdBindingFactAdapter, never()).listActiveBindingsByVin(anyString());
        verify(snapshotApplier, never()).apply(anyString(), anyString(), anyList(), anySet(), anyString());
    }

    @Test
    @DisplayName("空快照：解绑路径交由收敛器处理（快照集合为空）")
    void handle_shouldPassEmptySnapshot() {
        when(vmdBindingFactAdapter.listActiveBindingsByVin(anyString())).thenReturn(List.of());

        BindingFactEnrollmentAppService.Result result = appService.handle(event("VIN1"), "t");

        assertEquals(0, result.getSnapshotSize());
        ArgumentCaptor<Set<String>> snapshotSns = ArgumentCaptor.forClass(Set.class);
        verify(snapshotApplier).apply(anyString(), anyString(), anyList(), snapshotSns.capture(), anyString());
        assertTrue(snapshotSns.getValue().isEmpty());
    }
}
