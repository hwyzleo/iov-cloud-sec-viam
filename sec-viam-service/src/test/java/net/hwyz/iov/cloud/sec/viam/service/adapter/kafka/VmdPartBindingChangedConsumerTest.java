package net.hwyz.iov.cloud.sec.viam.service.adapter.kafka;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;
import net.hwyz.iov.cloud.sec.viam.service.adapter.kafka.dto.VmdPartBindingChangedPayload;
import net.hwyz.iov.cloud.sec.viam.service.application.service.BindingFactEnrollmentAppService;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.inbox.ViamInboxWriter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * 绑定变更事件消费者单元测试（SEC-VIAM-DSN-CR-006 / D-VIAM-029）
 *
 * @author hwyz_leo
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class VmdPartBindingChangedConsumerTest {

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private ViamInboxWriter inboxWriter;

    @Mock
    private BindingFactEnrollmentAppService appService;

    private VmdPartBindingChangedConsumer consumer;

    private static final String TOPIC = "vmd.vehicle-part-binding.changed";

    @BeforeEach
    void setUp() {
        consumer = new VmdPartBindingChangedConsumer(objectMapper, inboxWriter, appService);
        ReflectionTestUtils.setField(consumer, "sourceTopic", TOPIC);
    }

    private static VmdPartBindingChangedPayload payload(String eventId) {
        VmdPartBindingChangedPayload payload = new VmdPartBindingChangedPayload();
        payload.setEventId(eventId);
        payload.setVin("VIN1");
        payload.setBindingId(1L);
        payload.setChangeType("BIND");
        return payload;
    }

    @Test
    @DisplayName("载荷解析失败：丢弃且不落 Inbox")
    void onBindingChanged_shouldDropUnparsablePayload() throws Exception {
        when(objectMapper.readValue(anyString(), eq(VmdPartBindingChangedPayload.class)))
                .thenThrow(new IllegalArgumentException("bad json"));

        consumer.onBindingChanged("{bad}");

        verifyNoInteractions(inboxWriter);
        verifyNoInteractions(appService);
    }

    @Test
    @DisplayName("事件ID缺失（VMD直发事件）：按业务键派生稳定幂等键并继续处理")
    void onBindingChanged_shouldDeriveEventIdWhenMissing() throws Exception {
        VmdPartBindingChangedPayload p = payload(null);
        p.setSeq(44000L);
        p.setOccurredAt(java.time.Instant.parse("2026-11-16T13:38:55Z"));
        when(objectMapper.readValue(anyString(), eq(VmdPartBindingChangedPayload.class))).thenReturn(p);
        when(inboxWriter.tryRegister(anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(true);
        when(appService.handle(any(), eq(TOPIC)))
                .thenReturn(new BindingFactEnrollmentAppService.Result(1, List.of(), 1, 0, 0, 0, 0));

        consumer.onBindingChanged("{}");

        org.mockito.ArgumentCaptor<String> eventId = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(inboxWriter).tryRegister(eventId.capture(), eq("VEHICLE_PART_BINDING_CHANGED"), eq(TOPIC),
                anyString(), anyString());
        assertEquals(64, eventId.getValue().length());
        assertTrue(eventId.getValue().matches("[0-9a-f]{64}"));
        verify(inboxWriter).markProcessed(eventId.getValue());
    }

    @Test
    @DisplayName("同一无 eventId 事件重复投递：派生键稳定，Inbox 去重")
    void onBindingChanged_shouldDeriveStableKeyForRedelivery() throws Exception {
        VmdPartBindingChangedPayload p = payload(null);
        p.setSeq(44000L);
        p.setOccurredAt(java.time.Instant.parse("2026-11-16T13:38:55Z"));
        when(objectMapper.readValue(anyString(), eq(VmdPartBindingChangedPayload.class))).thenReturn(p);
        when(inboxWriter.tryRegister(anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(true, false);
        when(appService.handle(any(), eq(TOPIC)))
                .thenReturn(new BindingFactEnrollmentAppService.Result(1, List.of(), 1, 0, 0, 0, 0));

        consumer.onBindingChanged("{}");
        consumer.onBindingChanged("{}");

        org.mockito.ArgumentCaptor<String> eventId = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(inboxWriter, times(2)).tryRegister(eventId.capture(), anyString(), anyString(), anyString(), anyString());
        assertEquals(eventId.getAllValues().get(0), eventId.getAllValues().get(1));
        verify(appService, times(1)).handle(any(), anyString());
    }

    @Test
    @DisplayName("无法定位事件（vin/bindingId/seq 全空）：丢弃")
    void onBindingChanged_shouldDropUnidentifiableEvent() throws Exception {
        when(objectMapper.readValue(anyString(), eq(VmdPartBindingChangedPayload.class)))
                .thenReturn(new VmdPartBindingChangedPayload());

        consumer.onBindingChanged("{}");

        verifyNoInteractions(inboxWriter);
    }

    @Test
    @DisplayName("重复事件：Inbox 去重后直接返回")
    void onBindingChanged_shouldSkipDuplicate() throws Exception {
        when(objectMapper.readValue(anyString(), eq(VmdPartBindingChangedPayload.class)))
                .thenReturn(payload("evt-1"));
        when(inboxWriter.tryRegister(eq("evt-1"), eq("VEHICLE_PART_BINDING_CHANGED"), eq(TOPIC), anyString(), anyString()))
                .thenReturn(false);

        consumer.onBindingChanged("{}");

        verifyNoInteractions(appService);
        verify(inboxWriter, never()).markProcessed(anyString());
    }

    @Test
    @DisplayName("正常处理：标记 PROCESSED")
    void onBindingChanged_shouldMarkProcessed() throws Exception {
        when(objectMapper.readValue(anyString(), eq(VmdPartBindingChangedPayload.class)))
                .thenReturn(payload("evt-1"));
        when(inboxWriter.tryRegister(anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(true);
        when(appService.handle(any(), eq(TOPIC)))
                .thenReturn(new BindingFactEnrollmentAppService.Result(1, List.of(), 1, 0, 0, 0, 0));

        consumer.onBindingChanged("{}");

        verify(inboxWriter).markProcessed("evt-1");
        verify(inboxWriter, never()).markQuarantined(anyString(), anyString());
    }

    @Test
    @DisplayName("芯片 UID 缺失：事件隔离（可重放）")
    void onBindingChanged_shouldQuarantineWhenUidSkipped() throws Exception {
        when(objectMapper.readValue(anyString(), eq(VmdPartBindingChangedPayload.class)))
                .thenReturn(payload("evt-1"));
        when(inboxWriter.tryRegister(anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(true);
        when(appService.handle(any(), eq(TOPIC)))
                .thenReturn(new BindingFactEnrollmentAppService.Result(1, List.of("SN-X"), 0, 0, 0, 0, 0));

        consumer.onBindingChanged("{}");

        verify(inboxWriter).markQuarantined(eq("evt-1"), contains("SN-X"));
        verify(inboxWriter, never()).markProcessed(anyString());
    }

    @Test
    @DisplayName("业务门禁失败：隔离")
    void onBindingChanged_shouldQuarantineOnServiceException() throws Exception {
        when(objectMapper.readValue(anyString(), eq(VmdPartBindingChangedPayload.class)))
                .thenReturn(payload("evt-1"));
        when(inboxWriter.tryRegister(anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(true);
        when(appService.handle(any(), eq(TOPIC)))
                .thenThrow(new ViamServiceException(ViamErrorCode.PRINCIPAL_UID_UNAVAILABLE));

        consumer.onBindingChanged("{}");

        verify(inboxWriter).markQuarantined(eq("evt-1"), anyString());
    }

    @Test
    @DisplayName("未知异常：隔离重试")
    void onBindingChanged_shouldQuarantineOnUnexpectedException() throws Exception {
        when(objectMapper.readValue(anyString(), eq(VmdPartBindingChangedPayload.class)))
                .thenReturn(payload("evt-1"));
        when(inboxWriter.tryRegister(anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(true);
        when(appService.handle(any(), eq(TOPIC))).thenThrow(new IllegalStateException("boom"));

        consumer.onBindingChanged("{}");

        verify(inboxWriter).markQuarantined(eq("evt-1"), contains("boom"));
    }
}
