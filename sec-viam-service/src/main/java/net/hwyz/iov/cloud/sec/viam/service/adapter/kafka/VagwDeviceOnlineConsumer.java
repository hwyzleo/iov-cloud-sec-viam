package net.hwyz.iov.cloud.sec.viam.service.adapter.kafka;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.sec.viam.api.vo.DeviceOnlineEvidenceVo;
import net.hwyz.iov.cloud.sec.viam.service.application.service.SuccessfulDeviceLoginAppService;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.inbox.ViamInboxWriter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

/**
 * VAGW 设备上线事件消费者（SEC-VIAM-DSN-CR-001 / D-VIAM-007）
 * <p>
 * 消费 {@code vagw.device.online}；先按原 eventId 落 Inbox 去重，再进入成功接入闭环。
 * 缺可信证据时不写成功登录、不推进 ACTIVATING，标记隔离/重试（VAGW 配套就绪前
 * 成功接入链路尚未完成联调，如实标注，不阻断其它模块编码）。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class VagwDeviceOnlineConsumer {

    private final ObjectMapper objectMapper;
    private final ViamInboxWriter inboxWriter;
    private final SuccessfulDeviceLoginAppService successfulDeviceLoginAppService;

    @Value("${viam.kafka.topics.vagw-device-online:vagw.device.online}")
    private String sourceTopic;

    /**
     * 消费 VAGW DEVICE_ONLINE 事件。
     *
     * @param payload JSON 载荷（DeviceOnlineEvent 增强视图）
     */
    @KafkaListener(topics = "#{@viamKafkaTopicProperties.vagwDeviceOnline}", groupId = "sec-viam-device-online")
    public void onDeviceOnline(String payload) {
        DeviceOnlineEvidenceVo evidence;
        try {
            evidence = objectMapper.readValue(payload, DeviceOnlineEvidenceVo.class);
        } catch (Exception e) {
            log.error("DEVICE-ONLINE | 载荷解析失败: err={}", e.getMessage());
            return;
        }
        if (evidence == null || evidence.getEventId() == null) {
            log.warn("DEVICE-ONLINE | 事件ID缺失，丢弃");
            return;
        }
        // 先落 Inbox 去重（原 eventId）
        boolean firstSeen = inboxWriter.tryRegister(evidence.getEventId(), "DEVICE_ONLINE",
                sourceTopic, evidence.getAdmissionDecisionId(), payload);
        if (!firstSeen) {
            return;
        }
        try {
            successfulDeviceLoginAppService.handleDeviceOnline(evidence, sourceTopic);
            inboxWriter.markProcessed(evidence.getEventId());
        } catch (ViamServiceException e) {
            // 缺证据/证据不可信：隔离并保留重试，不写成功登录
            log.warn("DEVICE-ONLINE | 成功接入证据门禁未通过，隔离: eventId={}, code={}, reason={}",
                    evidence.getEventId(), e.getCode(), e.getMessage());
            inboxWriter.markQuarantined(evidence.getEventId(), e.getMessage());
        } catch (Exception e) {
            log.error("DEVICE-ONLINE | 处理失败，隔离重试: eventId={}, err={}", evidence.getEventId(), e.getMessage());
            inboxWriter.markQuarantined(evidence.getEventId(), e.getMessage());
        }
    }
}
