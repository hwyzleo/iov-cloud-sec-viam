package net.hwyz.iov.cloud.sec.viam.api.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * 批次治理操作结果VO（SEC-VIAM-DSN-CR-002 / D-VIAM-018）
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProvisioningOperationResultVo {

    /** 批次 requestId */
    private String requestId;

    /** 操作ID（= maintenanceRequestId，幂等键） */
    private String operationId;

    /** 操作前批次状态 */
    private String beforeStatus;

    /** 操作后批次状态 */
    private String afterStatus;

    /** 操作结果：SUCCESS / IDEMPOTENT_HIT */
    private String result;

    /** 操作发生时间 */
    private Instant occurredAt;
}
