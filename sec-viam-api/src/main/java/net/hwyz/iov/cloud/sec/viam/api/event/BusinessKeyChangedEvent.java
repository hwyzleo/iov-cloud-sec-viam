package net.hwyz.iov.cloud.sec.viam.api.event;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * 业务密钥目录变更事件（SEC-VIAM-DSN-CR-001 / FR-VIAM-003）
 * <p>
 * 对应 {@code viam.business-key.changed} / {@code viam.tbox-v2c-key-provisioned}（待登记新契约）。
 * 不含密钥材料/敏感字段。
 * </p>
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class BusinessKeyChangedEvent {

    /** 事件类型（契约稳定值） */
    public static final String EVENT_TYPE = "BUSINESS_KEY_CHANGED";

    /** 事件唯一ID（幂等键） */
    private String eventId;

    /** 设备序列号（key=deviceSn，完整用途集聚合事件） */
    private String deviceSn;

    /** 业务域（V2C_COMM） */
    private String businessDomain;

    /** 变更类型（PROVISIONED/ROTATED/REVOKED/CLEAR_BLOCKING） */
    private String changeType;

    /** 关联 requestId（Keyprov 批次幂等键） */
    private String requestId;

    /** 事件发生时间（UTC） */
    private Instant occurredAt;
}
