package net.hwyz.iov.cloud.sec.viam.api.vo;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.hwyz.iov.cloud.sec.viam.api.vo.enums.DeviceProofReasonCode;

import java.time.Instant;

/**
 * 设备证明校验结果VO（SEC-VIAM-DSN-CR-003 / FR-VIAM-3-1）
 * <p>
 * 只返回认证结论与 VIAM 已登记事实：不返回证书/签名原文、密钥材料、完整 VIN
 * 或任何可用于伪造身份的材料（FR-VIAM-3-6 / D-VIAM-3-08）。
 * {@code valid=true} 仅对应 {@link DeviceProofReasonCode#PROOF_VALID}。
 * </p>
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class DeviceProofVerifyResultVo {

    /** 证明是否有效（仅 PROOF_VALID 为 true） */
    private boolean valid;

    /** VIAM 安全主体ID（稳定 ID，非 hsmUid） */
    private String devicePrincipal;

    /** 设备序列号（取自 VIAM 资产映射事实，可空） */
    private String deviceSn;

    /** 设备安全开通状态（PRE_ACTIVE/ACTIVATING/ACTIVE/BLOCKED/RETIRED） */
    private String deviceStatus;

    /** 校验完成时间（UTC Instant） */
    private Instant verifiedAt;

    /** 结论原因码：PROOF_VALID/PROOF_INVALID/SUBJECT_UNAVAILABLE/DEPENDENCY_UNAVAILABLE/RATE_LIMITED */
    private String reasonCode;

    /**
     * 有效结论。
     */
    public static DeviceProofVerifyResultVo valid(String principalId, String deviceSn, String deviceStatus,
                                                  Instant verifiedAt) {
        return DeviceProofVerifyResultVo.builder()
                .valid(true)
                .devicePrincipal(principalId)
                .deviceSn(deviceSn)
                .deviceStatus(deviceStatus)
                .verifiedAt(verifiedAt)
                .reasonCode(DeviceProofReasonCode.PROOF_VALID.name())
                .build();
    }

    /**
     * 拒绝结论（fail-closed；不带主体信息，避免泄露设备事实）。
     */
    public static DeviceProofVerifyResultVo rejected(DeviceProofReasonCode reasonCode, Instant verifiedAt) {
        return DeviceProofVerifyResultVo.builder()
                .valid(false)
                .verifiedAt(verifiedAt)
                .reasonCode(reasonCode == null ? DeviceProofReasonCode.DEPENDENCY_UNAVAILABLE.name() : reasonCode.name())
                .build();
    }
}
