package net.hwyz.iov.cloud.sec.viam.service.application.service.deviceproof;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.sec.viam.service.common.util.ViamUtils;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SecurityOperationAudit;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.SecurityOperationAuditRepository;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 设备证明校验审计记录器（SEC-VIAM-DSN-CR-003 / D-VIAM-3-06 / FR-VIAM-3-6）
 * <p>
 * 复用既有安全操作审计载体 {@code tb_viam_security_operation_audit}（不新增表）：
 * {@code operation=DEVICE_PROOF_VERIFY}，只记录证明摘要、主体摘要、结论、原因码与耗时；
 * <b>不记录</b>证书/签名原文、完整 deviceId、VIN 或任何可伪造身份的材料。
 * 审计写入失败不改变已得结论，但记录 ERROR（可观测告警），不伪装为成功写入。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
public class DeviceProofAuditRecorder {

    /** 审计操作类型 */
    public static final String OPERATION = "DEVICE_PROOF_VERIFY";
    /** 未定位主体时的占位主体ID（与批次级 KEYPROV_BATCH 同一约定，列 NOT NULL） */
    public static final String PLACEHOLDER_PRINCIPAL = "DEVICE_PROOF";
    /** detail 列上限 */
    private static final int DETAIL_MAX_LENGTH = 512;
    /** caller_type 列上限 */
    private static final int CALLER_TYPE_MAX_LENGTH = 32;

    private final SecurityOperationAuditRepository auditRepository;
    private final ObjectMapper objectMapper;

    public DeviceProofAuditRecorder(SecurityOperationAuditRepository auditRepository, ObjectMapper objectMapper) {
        this.auditRepository = auditRepository;
        this.objectMapper = objectMapper;
    }

    /**
     * 落审计（best-effort；失败只告警，不改变结论）。
     *
     * @param requestId   本次校验请求ID（幂等键）
     * @param caller      调用方服务身份（X-Client-Id 自报，供审计识别）
     * @param principalId 已定位安全主体ID（可空；本身是派生ID，非明文 hsmUid）
     * @param proofType   证明类型
     * @param proofDigest 证明摘要
     * @param nonceDigest nonce 摘要
     * @param deviceId    设备标识线索（仅取摘要入审计）
     * @param reasonCode  结论原因码
     * @param errorCode   7027xx 内部错误码（可空）
     * @param elapsedMs   耗时（毫秒）
     * @param occurredAt  发生时间
     */
    public void record(String requestId, String caller, String principalId, String proofType, String proofDigest,
                       String nonceDigest, String deviceId, String reasonCode, String errorCode,
                       long elapsedMs, Instant occurredAt) {
        SecurityOperationAudit audit = SecurityOperationAudit.builder()
                .operationId(requestId)
                .principalId(isBlank(principalId) ? PLACEHOLDER_PRINCIPAL : principalId)
                .operation(OPERATION)
                .securityVersion(0L)
                .reason(reasonCode)
                .detail(buildDetail(proofType, proofDigest, nonceDigest, deviceId, reasonCode, errorCode, elapsedMs))
                .callerType(truncate(caller == null || caller.isBlank() ? "UNKNOWN" : caller,
                        CALLER_TYPE_MAX_LENGTH))
                .occurredAt(occurredAt == null ? Instant.now() : occurredAt)
                .build();
        try {
            auditRepository.save(audit);
        } catch (Exception e) {
            log.error("设备证明校验审计写入失败（不影响结论）: requestId={}, reason={}, err={}",
                    requestId, reasonCode, e.getMessage());
        }
    }

    private String buildDetail(String proofType, String proofDigest, String nonceDigest, String deviceId,
                               String reasonCode, String errorCode, long elapsedMs) {
        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("proofType", proofType);
        detail.put("proofDigest", proofDigest);
        detail.put("nonceDigest", nonceDigest);
        detail.put("deviceIdDigest", ViamUtils.sha256Hex(deviceId == null ? null : deviceId.trim()));
        detail.put("reasonCode", reasonCode);
        if (errorCode != null) {
            detail.put("errorCode", errorCode);
        }
        detail.put("elapsedMs", elapsedMs);
        try {
            return truncate(objectMapper.writeValueAsString(detail), DETAIL_MAX_LENGTH);
        } catch (Exception e) {
            // 序列化失败不得写入证明原文，只保留最小可读摘要
            return "{\"proofType\":\"" + proofType + "\",\"reasonCode\":\"" + reasonCode + "\"}";
        }
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private static String truncate(String value, int maxLength) {
        if (value == null || value.length() <= maxLength) {
            return value;
        }
        return value.substring(0, maxLength);
    }
}
