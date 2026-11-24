package net.hwyz.iov.cloud.sec.viam.service.adapter.kafka;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.sec.viam.service.adapter.kafka.dto.VmdPartBindingChangedPayload;
import net.hwyz.iov.cloud.sec.viam.service.application.service.BindingFactEnrollmentAppService;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import net.hwyz.iov.cloud.sec.viam.service.common.util.ViamUtils;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.inbox.ViamInboxWriter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

/**
 * VMD 车辆-零件绑定变更事件消费者（SEC-VIAM-DSN-CR-006 / D-VIAM-029）
 * <p>
 * 消费 {@code vmd.vehicle-part-binding.changed}；事件仅作触发信号，先按原 eventId 落 Inbox 去重，
 * 再回查 VMD active 绑定快照收敛安全主体与资产映射。
 * 芯片 UID 缺失/非法：单条跳过且事件置隔离（可重放恢复，重放对已收敛条目零副作用）。
 * </p>
 *
 * @author hwyz_leo
 * @since 2026-11-24
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class VmdPartBindingChangedConsumer {

    private static final String EVENT_TYPE = "VEHICLE_PART_BINDING_CHANGED";

    private final ObjectMapper objectMapper;
    private final ViamInboxWriter inboxWriter;
    private final BindingFactEnrollmentAppService bindingFactEnrollmentAppService;

    @Value("${viam.kafka.topics.vmd-part-binding-changed:vmd.vehicle-part-binding.changed}")
    private String sourceTopic;

    /**
     * 消费绑定变更事件。
     *
     * @param payload JSON 载荷
     */
    @KafkaListener(topics = "#{@viamKafkaTopicProperties.vmdPartBindingChanged}",
            groupId = "sec-viam-part-binding")
    public void onBindingChanged(String payload) {
        VmdPartBindingChangedPayload event;
        try {
            event = objectMapper.readValue(payload, VmdPartBindingChangedPayload.class);
        } catch (Exception e) {
            log.error("BINDING-CHANGED | 载荷解析失败: err={}", e.getMessage());
            return;
        }
        if (event == null) {
            log.warn("BINDING-CHANGED | 载荷为空，丢弃");
            return;
        }
        // VMD 直发事件不带 eventId（仅 Outbox 重放路径带）；缺省时按业务键派生稳定幂等键
        String eventId = resolveEventId(event);
        if (eventId == null) {
            log.warn("BINDING-CHANGED | 无法定位事件（vin/bindingId/seq 全空），丢弃");
            return;
        }
        String aggregateId = event.getBindingId() == null ? event.getVin() : String.valueOf(event.getBindingId());
        boolean firstSeen = inboxWriter.tryRegister(eventId, EVENT_TYPE, sourceTopic, aggregateId, payload);
        if (!firstSeen) {
            return;
        }
        try {
            BindingFactEnrollmentAppService.Result result = bindingFactEnrollmentAppService.handle(event, sourceTopic);
            if (result.hasSkipped()) {
                // 芯片 UID 缺失/非法：单条已跳过，事件隔离以便补齐后重放
                log.warn("BINDING-CHANGED | 芯片UID缺失，事件隔离待重放: eventId={}, skipped={}",
                        eventId, result.getSkippedDeviceSns());
                inboxWriter.markQuarantined(eventId,
                        "uid unavailable: " + result.getSkippedDeviceSns());
                return;
            }
            inboxWriter.markProcessed(eventId);
        } catch (ViamServiceException e) {
            log.warn("BINDING-CHANGED | 事实门禁未通过，隔离: eventId={}, code={}, reason={}",
                    eventId, e.getCode(), e.getMessage());
            inboxWriter.markQuarantined(eventId, e.getMessage());
        } catch (Exception e) {
            log.error("BINDING-CHANGED | 处理失败，隔离重试: eventId={}, err={}", eventId, e.getMessage());
            inboxWriter.markQuarantined(eventId, e.getMessage());
        }
    }

    /**
     * 解析幂等事件键：优先使用事件自带 eventId；否则按业务键派生稳定 SHA-256
     * <p>
     * VMD 的 `VehiclePartBindingKafkaProducer` 直发事件不含 eventId（仅 Outbox 重放路径带），
     * 因此以 `vin|bindingId|changeType|seq|occurredAt` 派生 64 位十六进制键：
     * 同一事件重投得到相同键（Inbox 去重），不同事件键不同。
     * </p>
     *
     * @param event 事件载荷
     * @return 幂等键；无法定位事件时返回 null
     */
    private static String resolveEventId(VmdPartBindingChangedPayload event) {
        if (event.getEventId() != null && !event.getEventId().isBlank()) {
            return event.getEventId().trim();
        }
        String raw = nullToEmpty(event.getVin()) + '|'
                + (event.getBindingId() == null ? "" : event.getBindingId()) + '|'
                + nullToEmpty(event.getChangeType()) + '|'
                + (event.getSeq() == null ? "" : event.getSeq()) + '|'
                + (event.getOccurredAt() == null ? "" : event.getOccurredAt().toString());
        if (raw.replace("|", "").isEmpty()) {
            return null;
        }
        return ViamUtils.sha256Hex(raw);
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }
}
