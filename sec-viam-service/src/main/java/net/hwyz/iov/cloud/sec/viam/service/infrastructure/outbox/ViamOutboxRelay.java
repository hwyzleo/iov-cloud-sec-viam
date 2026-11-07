package net.hwyz.iov.cloud.sec.viam.service.infrastructure.outbox;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.framework.kafka.topic.KafkaTopicProvisioningStatus;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.mapper.ViamOutboxMapper;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.ViamOutboxPo;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * VIAM Outbox 发布器（SEC-VIAM-DSN-CR-001 / D-VIAM-008）
 * <p>
 * 事务性发件箱的发布端：定时扫描 {@code tb_viam_outbox} 中 PENDING/FAILED_RETRYABLE 事件，
 * 按固化 topic/messageKey/payload 原样发布到 Kafka，broker 确认后幂等标记 PUBLISHED。
 * <ul>
 *   <li>Readiness 门禁：{@code viam.kafka.readiness.gate-producer=true} 时 Topic Provisioning
 *       未就绪（NOT_READY）不硬发，事件留在 Outbox 后台重试；</li>
 *   <li>发布失败：{@code retry_count+1} 并按固定间隔安排 {@code next_retry_time}；超过最大重试
 *       次数置 DEAD 终态终止；</li>
 *   <li>非法记录（topic 为空）：直接置 DEAD，不浪费重试；</li>
 *   <li>at-least-once：发布成功但状态回写失败时下次扫描会重发，由消费端按 eventId 幂等去重
 *       （与 CR-001「重复事件不双发」的消费端幂等约束一致）。</li>
 * </ul>
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
@RequiredArgsConstructor
@ConditionalOnProperty(name = "viam.outbox.relay.enabled", havingValue = "true", matchIfMissing = true)
public class ViamOutboxRelay {

    private static final int MAX_ERROR_LENGTH = 2000;

    private final ViamOutboxMapper outboxMapper;
    private final KafkaTemplate<String, String> kafkaTemplate;
    private final ObjectProvider<KafkaTopicProvisioningStatus> provisioningStatusProvider;

    @Value("${viam.outbox.relay.batch-size:100}")
    private int batchSize;

    @Value("${viam.outbox.relay.max-retry:3}")
    private int maxRetry;

    @Value("${viam.outbox.relay.retry-interval-seconds:60}")
    private int retryIntervalSeconds;

    @Value("${viam.outbox.relay.publish-timeout-ms:10000}")
    private long publishTimeoutMs;

    @Value("${viam.kafka.readiness.gate-producer:true}")
    private boolean gateProducer;

    /**
     * 定时扫描并发布待发布事件。
     */
    @Scheduled(fixedDelayString = "${viam.outbox.relay.scan-interval-ms:5000}")
    public void relayPending() {
        if (gateProducer && !producerTopicsReady()) {
            log.warn("VIAM 生产 Topic readiness 未就绪，暂停 Outbox Relay 发布（事件保留待重试）");
            return;
        }
        List<ViamOutboxPo> pending = outboxMapper.selectPending(batchSize);
        if (pending.isEmpty()) {
            return;
        }
        log.info("Outbox Relay 扫描到 {} 条待发布事件", pending.size());
        for (ViamOutboxPo outbox : pending) {
            try {
                publish(outbox);
            } catch (IllegalArgumentException e) {
                markDead(outbox, "非法 Outbox 记录: " + e.getMessage());
            } catch (Exception e) {
                handleFailure(outbox, e);
            }
        }
    }

    /**
     * 发布单条事件并回写 PUBLISHED（同步等待 broker 确认，保证状态机确定迁移）。
     */
    private void publish(ViamOutboxPo outbox) throws Exception {
        if (outbox.getTopic() == null || outbox.getTopic().isBlank()) {
            throw new IllegalArgumentException("topic 为空: eventId=" + outbox.getEventId());
        }
        log.debug("发布事件到 Kafka: eventId={}, topic={}, key={}",
                outbox.getEventId(), outbox.getTopic(), outbox.getMessageKey());
        CompletableFuture<SendResult<String, String>> future = kafkaTemplate.send(
                outbox.getTopic(), outbox.getMessageKey(), outbox.getPayload());
        future.get(publishTimeoutMs, TimeUnit.MILLISECONDS);
        outboxMapper.markPublished(outbox.getEventId(), LocalDateTime.now());
        log.info("事件发布成功: eventId={}, topic={}", outbox.getEventId(), outbox.getTopic());
    }

    /**
     * 发布失败：重试计数+1，未超限安排下次重试；超限置 DEAD。
     */
    private void handleFailure(ViamOutboxPo outbox, Throwable e) {
        int retryCount = outbox.getRetryCount() + 1;
        String error = truncate(e.getMessage());
        if (retryCount >= maxRetry) {
            outboxMapper.markDead(outbox.getEventId(), error);
            log.error("Outbox 事件超过最大重试次数，置 DEAD: eventId={}, retryCount={}, error={}",
                    outbox.getEventId(), retryCount, error);
            return;
        }
        LocalDateTime nextRetryTime = LocalDateTime.now().plusSeconds(retryIntervalSeconds);
        outboxMapper.markFailedRetryable(outbox.getEventId(), retryCount, nextRetryTime, error);
        log.warn("Outbox 事件发布失败，待重试: eventId={}, retryCount={}, nextRetryTime={}, error={}",
                outbox.getEventId(), retryCount, nextRetryTime, error);
    }

    /**
     * 非法记录直接置 DEAD（终态，不重试）。
     */
    private void markDead(ViamOutboxPo outbox, String error) {
        outboxMapper.markDead(outbox.getEventId(), truncate(error));
        log.error("Outbox 事件置 DEAD: eventId={}, error={}", outbox.getEventId(), error);
    }

    /**
     * Producer 就绪门禁：Topic Provisioning 未 READY 时不静默发送，保留 Outbox 并后台重试。
     */
    private boolean producerTopicsReady() {
        KafkaTopicProvisioningStatus status = provisioningStatusProvider.getIfAvailable();
        return status == null || status.state() != KafkaTopicProvisioningStatus.State.NOT_READY;
    }

    private String truncate(String error) {
        if (error == null) {
            return null;
        }
        return error.length() <= MAX_ERROR_LENGTH
                ? error
                : error.substring(0, MAX_ERROR_LENGTH - 3) + "...";
    }
}
