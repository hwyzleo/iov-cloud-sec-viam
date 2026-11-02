package net.hwyz.iov.cloud.sec.viam.service.infrastructure.outbox;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.mapper.ViamOutboxMapper;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.ViamOutboxPo;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * VIAM Outbox 写入器（SEC-VIAM-DSN-CR-001 / D-VIAM-008）
 * <p>
 * 与业务写入同事务落 Outbox（事务性发件箱），由 Relay 扫描发布到 Kafka；
 * eventId 幂等，重复发布不产生双发。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ViamOutboxWriter {

    private final ViamOutboxMapper outboxMapper;

    /**
     * 写入一条待发布事件（幂等：eventId 已存在则忽略）。
     *
     * @param eventId        事件ID（幂等键）
     * @param eventType      事件类型
     * @param aggregateType  聚合类型
     * @param aggregateId    聚合ID
     * @param topic          Kafka Topic
     * @param messageKey     Kafka Message Key
     * @param payloadJson    事件 payload（JSON）
     * @param sourceType     来源类型（可选）
     * @param sourceRefId    来源引用ID（可选）
     */
    public void enqueue(String eventId, String eventType, String aggregateType, String aggregateId,
                        String topic, String messageKey, String payloadJson,
                        String sourceType, String sourceRefId) {
        ViamOutboxPo existing = outboxMapper.selectByEventId(eventId);
        if (existing != null) {
            log.debug("Outbox事件已存在，幂等忽略: eventId={}", eventId);
            return;
        }
        ViamOutboxPo po = ViamOutboxPo.builder()
                .eventId(eventId)
                .eventType(eventType)
                .aggregateType(aggregateType)
                .aggregateId(aggregateId)
                .topic(topic)
                .messageKey(messageKey)
                .payload(payloadJson)
                .publishState("PENDING")
                .retryCount(0)
                .sourceType(sourceType)
                .sourceRefId(sourceRefId)
                .build();
        outboxMapper.insert(po);
        log.info("Outbox写入待发布事件: eventId={}, topic={}, key={}", eventId, topic, messageKey);
    }

    /**
     * 生成事件ID。
     */
    public static String newEventId() {
        return UUID.randomUUID().toString().replace("-", "");
    }
}
