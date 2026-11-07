package net.hwyz.iov.cloud.sec.viam.service.infrastructure.outbox;

import net.hwyz.iov.cloud.framework.kafka.topic.KafkaTopicProvisioningStatus;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.mapper.ViamOutboxMapper;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.ViamOutboxPo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.List;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Outbox Relay 单元测试（SEC-VIAM-DSN-CR-001 / D-VIAM-008）
 * <p>
 * 验证：PENDING → 发布成功 → PUBLISHED（payload 原样）；发布失败重试/超限 DEAD；
 * readiness NOT_READY 暂停发布；非法 topic 直接 DEAD；空队列不动作。
 *
 * @author hwyz_leo
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("ViamOutboxRelay 测试")
class ViamOutboxRelayTest {

    private static final String EVENT_ID = "5a46dbcd28f542e0aff4a93423f9bc36";
    private static final String TOPIC = "viam.device.login-succeeded";
    private static final String KEY = "PR-e0cca2965509df678c8064f5";
    private static final String PAYLOAD = "{\"eventId\":\"" + EVENT_ID + "\",\"principalId\":\"" + KEY + "\"}";

    @Mock
    private ViamOutboxMapper outboxMapper;

    @Mock
    private KafkaTemplate<String, String> kafkaTemplate;

    @Mock
    private ObjectProvider<KafkaTopicProvisioningStatus> provisioningStatusProvider;

    private ViamOutboxRelay relay;

    @BeforeEach
    void setUp() {
        relay = new ViamOutboxRelay(outboxMapper, kafkaTemplate, provisioningStatusProvider);
        ReflectionTestUtils.setField(relay, "batchSize", 100);
        ReflectionTestUtils.setField(relay, "maxRetry", 3);
        ReflectionTestUtils.setField(relay, "retryIntervalSeconds", 60);
        ReflectionTestUtils.setField(relay, "publishTimeoutMs", 10_000L);
        ReflectionTestUtils.setField(relay, "gateProducer", true);
    }

    private ViamOutboxPo outbox(String state, int retryCount) {
        return ViamOutboxPo.builder()
                .eventId(EVENT_ID)
                .eventType("DEVICE_LOGIN_SUCCEEDED")
                .aggregateType("SECURITY_PRINCIPAL")
                .aggregateId(KEY)
                .topic(TOPIC)
                .messageKey(KEY)
                .payload(PAYLOAD)
                .publishState(state)
                .retryCount(retryCount)
                .build();
    }

    @Test
    @DisplayName("PENDING 事件发布成功：payload 原样发送并标记 PUBLISHED")
    void publishSuccessMarksPublished() {
        when(outboxMapper.selectPending(100)).thenReturn(List.of(outbox("PENDING", 0)));
        when(kafkaTemplate.send(TOPIC, KEY, PAYLOAD))
                .thenReturn(CompletableFuture.completedFuture(mock(SendResult.class)));

        relay.relayPending();

        ArgumentCaptor<String> topicCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> keyCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> payloadCaptor = ArgumentCaptor.forClass(String.class);
        verify(kafkaTemplate).send(topicCaptor.capture(), keyCaptor.capture(), payloadCaptor.capture());
        assertEquals(TOPIC, topicCaptor.getValue());
        assertEquals(KEY, keyCaptor.getValue());
        assertEquals(PAYLOAD, payloadCaptor.getValue(), "payload 必须原样发布，不允许改写");

        ArgumentCaptor<LocalDateTime> publishedAtCaptor = ArgumentCaptor.forClass(LocalDateTime.class);
        verify(outboxMapper).markPublished(eq(EVENT_ID), publishedAtCaptor.capture());
        assertNotNull(publishedAtCaptor.getValue());
    }

    @Test
    @DisplayName("发布失败：retry_count+1 并安排 next_retry_time，未超限保持 FAILED_RETRYABLE")
    void publishFailureSchedulesRetry() {
        when(outboxMapper.selectPending(100)).thenReturn(List.of(outbox("PENDING", 0)));
        when(kafkaTemplate.send(TOPIC, KEY, PAYLOAD))
                .thenReturn(CompletableFuture.failedFuture(new RuntimeException("broker down")));

        relay.relayPending();

        ArgumentCaptor<LocalDateTime> nextRetryCaptor = ArgumentCaptor.forClass(LocalDateTime.class);
        verify(outboxMapper).markFailedRetryable(eq(EVENT_ID), eq(1), nextRetryCaptor.capture(), anyString());
        assertNotNull(nextRetryCaptor.getValue());
        verify(outboxMapper, never()).markDead(anyString(), anyString());
        verify(outboxMapper, never()).markPublished(anyString(), any());
    }

    @Test
    @DisplayName("重试耗尽：置 DEAD 终态，不再重试")
    void retryExhaustedMarksDead() {
        when(outboxMapper.selectPending(100)).thenReturn(List.of(outbox("FAILED_RETRYABLE", 2)));
        when(kafkaTemplate.send(TOPIC, KEY, PAYLOAD))
                .thenReturn(CompletableFuture.failedFuture(new RuntimeException("broker down")));

        relay.relayPending();

        verify(outboxMapper).markDead(eq(EVENT_ID), anyString());
        verify(outboxMapper, never()).markFailedRetryable(anyString(), anyInt(), any(), anyString());
    }

    @Test
    @DisplayName("readiness NOT_READY：暂停发布，不触碰 Kafka 与状态机")
    void readinessNotReadyPausesPublish() {
        KafkaTopicProvisioningStatus status = mock(KafkaTopicProvisioningStatus.class);
        when(status.state()).thenReturn(KafkaTopicProvisioningStatus.State.NOT_READY);
        when(provisioningStatusProvider.getIfAvailable()).thenReturn(status);

        relay.relayPending();

        verifyNoInteractions(kafkaTemplate);
        verifyNoInteractions(outboxMapper);
    }

    @Test
    @DisplayName("readiness DISABLED/READY：正常发布")
    void readinessReadyAllowsPublish() {
        KafkaTopicProvisioningStatus status = mock(KafkaTopicProvisioningStatus.class);
        when(status.state()).thenReturn(KafkaTopicProvisioningStatus.State.READY);
        when(provisioningStatusProvider.getIfAvailable()).thenReturn(status);
        when(outboxMapper.selectPending(100)).thenReturn(List.of(outbox("PENDING", 0)));
        when(kafkaTemplate.send(TOPIC, KEY, PAYLOAD))
                .thenReturn(CompletableFuture.completedFuture(mock(SendResult.class)));

        relay.relayPending();

        verify(kafkaTemplate).send(TOPIC, KEY, PAYLOAD);
        verify(outboxMapper).markPublished(eq(EVENT_ID), any());
    }

    @Test
    @DisplayName("无 readiness Bean（未启用 Topic Provisioning）：视为就绪，正常发布")
    void noReadinessBeanAllowsPublish() {
        when(provisioningStatusProvider.getIfAvailable()).thenReturn(null);
        when(outboxMapper.selectPending(100)).thenReturn(List.of(outbox("PENDING", 0)));
        when(kafkaTemplate.send(TOPIC, KEY, PAYLOAD))
                .thenReturn(CompletableFuture.completedFuture(mock(SendResult.class)));

        relay.relayPending();

        verify(kafkaTemplate).send(TOPIC, KEY, PAYLOAD);
        verify(outboxMapper).markPublished(eq(EVENT_ID), any());
    }

    @Test
    @DisplayName("topic 为空：非法记录直接置 DEAD，不重试")
    void blankTopicMarksDead() {
        ViamOutboxPo bad = outbox("PENDING", 0);
        bad.setTopic(null);
        when(outboxMapper.selectPending(100)).thenReturn(List.of(bad));

        relay.relayPending();

        verify(outboxMapper).markDead(eq(EVENT_ID), anyString());
        verifyNoInteractions(kafkaTemplate);
        verify(outboxMapper, never()).markFailedRetryable(anyString(), anyInt(), any(), anyString());
    }

    @Test
    @DisplayName("空队列：不动作")
    void emptyQueueNoop() {
        when(outboxMapper.selectPending(100)).thenReturn(List.of());

        relay.relayPending();

        verifyNoInteractions(kafkaTemplate);
        verify(outboxMapper, never()).markPublished(anyString(), any());
        verify(outboxMapper, never()).markDead(anyString(), anyString());
    }

    @Test
    @DisplayName("失败时 last_error 超长被截断")
    void failureErrorTruncated() {
        when(outboxMapper.selectPending(100)).thenReturn(List.of(outbox("PENDING", 0)));
        String longError = "x".repeat(3000);
        when(kafkaTemplate.send(TOPIC, KEY, PAYLOAD))
                .thenReturn(CompletableFuture.failedFuture(new RuntimeException(longError)));

        relay.relayPending();

        ArgumentCaptor<String> errorCaptor = ArgumentCaptor.forClass(String.class);
        verify(outboxMapper).markFailedRetryable(eq(EVENT_ID), eq(1), any(), errorCaptor.capture());
        assertEquals(2000, errorCaptor.getValue().length());
    }
}
