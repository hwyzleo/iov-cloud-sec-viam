package net.hwyz.iov.cloud.sec.viam.api.vo;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * 批次级一键清阻断请求VO（SEC-VIAM-DSN-CR-002 / D-VIAM-018）
 * <p>
 * 唯一破坏性后台入口：服务端在事务内重做全部门禁（幂等键、状态允许集、
 * 期望状态一致、期望修改时间一致），不依赖客户端「先查后写」判断。
 * </p>
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProvisioningClearBlockingVo {

    /** 维护请求ID（幂等键，重复提交返回同一结果） */
    @NotBlank(message = "maintenanceRequestId不能为空")
    private String maintenanceRequestId;

    /** 期望批次状态（乐观并发校验） */
    @NotBlank(message = "expectedState不能为空")
    private String expectedState;

    /** 期望批次修改时间（乐观并发校验） */
    @NotNull(message = "expectedModifyTime不能为空")
    private Instant expectedModifyTime;

    /** 原因码（受治理枚举：ACK_TIMEOUT/QUARANTINE_MIGRATION/PROVIDER_UNKNOWN/MANUAL_OPERATION 等） */
    @NotBlank(message = "reasonCode不能为空")
    private String reasonCode;

    /** 原因说明 */
    @NotBlank(message = "reason不能为空")
    private String reason;

    /** 关联工单号 */
    @NotBlank(message = "ticketNo不能为空")
    private String ticketNo;
}
