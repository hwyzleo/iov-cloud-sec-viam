package net.hwyz.iov.cloud.sec.viam.service.domain.model.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

/**
 * 安全操作审计（SEC-VIAM-DSN-CR-001 / FR-VIAM-008 / T05）
 * <p>
 * 不可篡改的操作事实：block/unblock/retire/revoke/unbind/rotate/clear-blocking 等，
 * 记录真实操作人（EIAM 用户或受信 workload）、原因、变更后安全版本。
 * </p>
 *
 * @author hwyz_leo
 */
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityOperationAudit {

    /** 主键（DB 自增） */
    private Long id;

    /** 操作ID（幂等键） */
    private String operationId;

    /** 安全主体ID */
    private String principalId;

    /** 归一化 HSM UID */
    private String hsmUid;

    /** 车辆VIN */
    private String vin;

    /** 设备序列号 */
    private String deviceSn;

    /** 操作类型（BLOCK/UNBLOCK/RETIRE/REVOKE/UNBIND/REPLACEMENT/ROTATE/CLEAR_BLOCKING/ACCESS_INVALIDATION） */
    private String operation;

    /** 操作后安全状态版本 */
    private long securityVersion;

    /** 操作原因/说明 */
    private String reason;

    /** 操作详情（非敏感） */
    private String detail;

    /** 真实操作人 */
    private String operatorId;

    /** 操作人名称 */
    private String operatorName;

    /** 调用方类型（MPT_ADMIN/VAGW/OAPI_MES） */
    private String callerType;

    /** 操作发生时间（安全状态提交时间） */
    private Instant occurredAt;
}
