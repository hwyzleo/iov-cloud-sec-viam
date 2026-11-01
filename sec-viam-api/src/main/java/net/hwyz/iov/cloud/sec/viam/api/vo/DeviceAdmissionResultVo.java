package net.hwyz.iov.cloud.sec.viam.api.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.hwyz.iov.cloud.sec.viam.api.vo.enums.AdmissionDecision;
import net.hwyz.iov.cloud.sec.viam.api.vo.enums.AdmissionReason;
import net.hwyz.iov.cloud.sec.viam.api.vo.enums.BindStatus;
import net.hwyz.iov.cloud.sec.viam.api.vo.enums.CertificateStatus;
import net.hwyz.iov.cloud.sec.viam.api.vo.enums.DeviceStatus;

import java.time.Instant;

/**
 * 设备接入准入裁决结果VO（SEC-VIAM-DSN-CR-001 / FR-VIAM-004）
 * <p>
 * ALLOW 时 reason=NONE 且 vin、bindStatus=BOUND、certStatus=VALID、deviceStatus、bindVersion、updatedAt 必须存在；
 * DENY 时尽可能返回已确定状态，不可确定的字段允许为空，但不得伪造 VALID。
 * ALLOW 表示认证/准入通过，不等于成功建链；成功接入记录以可信 connected 证据为准（FR-VIAM-005）。
 * </p>
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DeviceAdmissionResultVo {

    /** 裁决结果 */
    private AdmissionDecision decision;

    /** 裁决原因（语义枚举） */
    private AdmissionReason reason;

    /** 车辆识别码（ALLOW 必填） */
    private String vin;

    /** 绑定状态 */
    private BindStatus bindStatus;

    /** 证书状态 */
    private CertificateStatus certStatus;

    /** 设备安全开通准入态 */
    private DeviceStatus deviceStatus;

    /** 绑定版本（ALLOW 必填） */
    private Long bindVersion;

    /** 事实更新时间：max(binding.lastEventTime, tbox.modifyTime, certificate.checkedAt) */
    private Instant updatedAt;

    /** VIAM 准入裁决ID（决策审计关联键；VAGW 成功接入证据需引用） */
    private String admissionDecisionId;
}
