package net.hwyz.iov.cloud.sec.viam.api.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import jakarta.validation.constraints.NotBlank;

/**
 * 设备证书申请请求VO（SEC-VIAM-DSN-CR-001 / FR-VIAM-002）
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CertificateApplyVo {

    /** MES/OAPI业务请求幂等键 */
    @NotBlank(message = "requestId不能为空")
    private String requestId;

    /** 车辆VIN */
    @NotBlank(message = "vin不能为空")
    private String vin;

    /** 设备类别 */
    @NotBlank(message = "deviceCategory不能为空")
    private String deviceCategory;

    /** 设备SN（物理实例序列号） */
    @NotBlank(message = "deviceSn不能为空")
    private String deviceSn;

    /** 调用方声明 ecu_uid（可选；非权威，以受信绑定解析的 hsm_uid 为准） */
    private String ecuUid;

    /** 证书Profile（受治理逻辑Profile名） */
    @NotBlank(message = "certificateProfile不能为空")
    private String certificateProfile;

    /** CSR DER Base64编码 */
    @NotBlank(message = "csrDerBase64不能为空")
    private String csrDerBase64;

    /** 来源系统 */
    private String sourceSystem;

    /** MES原请求号（人工补偿关联） */
    private String originalRequestId;

    /** 人工补偿原因 */
    private String compensationReason;

    /** 关联工单号 */
    private String ticketNo;

    /** 操作人ID */
    private String operatorId;

    /** 产线设备号 */
    private String facilityNo;

    /** 产线工位代码 */
    private String lineCode;
}
