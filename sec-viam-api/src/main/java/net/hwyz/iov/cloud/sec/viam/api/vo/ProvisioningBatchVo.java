package net.hwyz.iov.cloud.sec.viam.api.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;

/**
 * 业务密钥开通批次治理视图VO（SEC-VIAM-DSN-CR-002 / D-VIAM-017 / D-VIAM-018）
 * <p>
 * 只读运维视图：不含响应密文、信封字节、wrappedKey、密钥材料与 digest 原始字节。
 * </p>
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProvisioningBatchVo {

    /** 批次 requestId */
    private String requestId;

    /** 设备SN */
    private String deviceSn;

    /** 业务域 */
    private String businessDomain;

    /** 批次状态 */
    private String status;

    /** 非敏感失败原因 */
    private String failReason;

    /** KL1 标识 */
    private String lifecycleProfile;

    /** KL1 F：首次完整响应持久化时间 */
    private Instant firstIssuedAt;

    /** KL1 B：固定ACK截止时间 */
    private Instant ackDeadlineAt;

    /** 当前最大交付租约序号 */
    private Integer leaseSeq;

    /** 终态治理原因 */
    private String terminalReason;

    /** 终态治理时间 */
    private Instant terminalAt;

    /** 开始时间 */
    private Instant startedAt;

    /** 首次完整ACK时间 */
    private Instant acknowledgedAt;

    /** 完成时间 */
    private Instant completedAt;

    /** 修改时间（破坏性操作期望版本锚点） */
    private Instant modifyTime;

    /** 记录版本（破坏性操作期望版本锚点） */
    private Integer rowVersion;

    /** 阻塞判定：LOCAL_DIRECTORY / BATCH / NONE */
    private String blockingLevel;

    /** 阻塞原因（非敏感） */
    private String blockingReason;

    /** 逐用途明细 */
    private List<ProvisioningItemVo> items;

    /** 最近交付租约 */
    private ProvisioningLeaseVo lease;
}
