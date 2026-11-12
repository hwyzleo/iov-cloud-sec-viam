package net.hwyz.iov.cloud.sec.viam.api.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * 业务密钥开通批次用途明细治理视图VO（SEC-VIAM-DSN-CR-002 / D-VIAM-017）
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProvisioningItemVo {

    /** 用途（UPLINK_AEAD / DOWNLINK_AEAD） */
    private String purpose;

    /** 业务版本 */
    private Long businessKeyVersion;

    /** 目录 keyId（不透明标识） */
    private String keyId;

    /** 根版本（仅根派生型） */
    private Long rootKeyVersion;

    /** 派生格式版本 */
    private String derivationVersion;

    /** 信封格式 */
    private String envelopeFormat;

    /** 设备确认结果：PENDING/SUCCEEDED/FAILED/UNKNOWN */
    private String deviceResult;

    /** 单用途确认时间 */
    private Instant confirmedAt;

    /** 对应目录行状态（查不到时为空） */
    private String directoryKeyState;

    /** 目录行当前业务版本（查不到时为空） */
    private Long directoryBusinessKeyVersion;
}
