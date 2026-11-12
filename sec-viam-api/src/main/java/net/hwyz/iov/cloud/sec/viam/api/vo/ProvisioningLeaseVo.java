package net.hwyz.iov.cloud.sec.viam.api.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * 业务密钥交付租约治理视图VO（SEC-VIAM-DSN-CR-002 / D-VIAM-017）
 * <p>
 * 只暴露租约窗口与序号，不返回租约载荷与摘要字节。
 * </p>
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProvisioningLeaseVo {

    /** 租约序号 */
    private Integer leaseSeq;

    /** 签发时间 */
    private Instant issuedAt;

    /** 过期时间（KL1 E） */
    private Instant expireAt;

    /** 应用投递 messageId */
    private String messageId;
}
