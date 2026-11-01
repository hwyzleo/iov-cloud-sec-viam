package net.hwyz.iov.cloud.sec.viam.service.infrastructure.inbox;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.sec.viam.service.common.util.ViamUtils;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.mapper.ViamInboxMapper;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.ViamInboxPo;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

/**
 * VIAM Inbox 写入器（SEC-VIAM-DSN-CR-001 / D-VIAM-008）
 * <p>
 * 入站事件先按原 eventId 落 Inbox 去重，再处理；重复事件幂等返回已处理。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ViamInboxWriter {

    private final ViamInboxMapper inboxMapper;

    /**
     * 尝试登记入站事件（幂等去重）。
     *
     * @return true=首次登记可处理；false=重复事件已登记
     */
    public boolean tryRegister(String eventId, String eventType, String sourceTopic, String sourceRefId, String payloadJson) {
        ViamInboxPo existing = inboxMapper.selectByEventId(eventId);
        if (existing != null) {
            log.info("Inbox重复事件，按原eventId去重: eventId={}", eventId);
            return false;
        }
        ViamInboxPo po = ViamInboxPo.builder()
                .eventId(eventId)
                .eventType(eventType)
                .sourceTopic(sourceTopic)
                .sourceRefId(sourceRefId)
                .payloadDigest(ViamUtils.sha256Hex(payloadJson))
                .receivedAt(LocalDateTime.now())
                .processedState("PENDING")
                .retryCount(0)
                .build();
        inboxMapper.insertPo(po);
        return true;
    }

    /**
     * 标记处理完成。
     */
    public void markProcessed(String eventId) {
        ViamInboxPo po = inboxMapper.selectByEventId(eventId);
        if (po == null) {
            return;
        }
        po.setProcessedState("PROCESSED");
        inboxMapper.updatePo(po);
    }

    /**
     * 标记隔离（缺可信证据/乱序），保留重试。
     */
    public void markQuarantined(String eventId, String reason) {
        ViamInboxPo po = inboxMapper.selectByEventId(eventId);
        if (po == null) {
            return;
        }
        po.setProcessedState("QUARANTINED");
        po.setQuarantineReason(reason);
        po.setRetryCount(po.getRetryCount() + 1);
        inboxMapper.updatePo(po);
    }
}
