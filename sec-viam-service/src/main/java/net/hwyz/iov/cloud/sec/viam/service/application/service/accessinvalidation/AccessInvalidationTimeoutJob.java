package net.hwyz.iov.cloud.sec.viam.service.application.service.accessinvalidation;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.AccessInvalidationRecord;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.AccessInvalidationRepository;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;

/**
 * 访问失效超时对账调度（SEC-VIAM-DSN-CR-001 / FR-VIAM-008 / G-3）
 * <p>
 * 超过生效时限（effectiveBy，从安全状态提交时间 F 起算）仍未确认执行的 PENDING 记录
 * 标记 TIMEOUT 并触发超时告警（此处记录日志；告警通道由监控接入）。生效时限不得在
 * 事件消费时重新起算。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AccessInvalidationTimeoutJob {

    private static final int SCAN_LIMIT = 500;

    private final AccessInvalidationRepository invalidationRepository;

    @Scheduled(fixedDelayString = "${viam.access-invalidation.timeout-scan-ms:30000}")
    public void scanTimeouts() {
        Instant now = Instant.now();
        List<AccessInvalidationRecord> overdue = invalidationRepository.listPendingBefore(now, SCAN_LIMIT);
        for (AccessInvalidationRecord record : overdue) {
            if (record.isTimeoutAlerted()) {
                continue;
            }
            record.setStatus(AccessInvalidationRecord.STATUS_TIMEOUT);
            record.setTimeoutAlerted(true);
            invalidationRepository.save(record);
            log.warn("访问失效执行超时告警: invalidationId={}, principalId={}, effectiveBy={}, retryCount={}",
                    record.getInvalidationId(), record.getPrincipalId(), record.getEffectiveBy(),
                    record.getRetryCount());
        }
    }
}
