package net.hwyz.iov.cloud.sec.viam.api.vo;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 证书人工补申请请求VO（SEC-VIAM-DSN-CR-002 / FR-VIAM-002 / D-VIAM-014）
 * <p>
 * 后台不生成设备密钥或 CSR：csrDerBase64 必须来自目标设备侧受信工位回读；
 * Subject CN 与 hsm_uid 一致性校验由应用服务按设备侧同一套语义执行。
 * operatorId 不由客户端提供，一律取当前 EIAM 认证用户。
 * </p>
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CertificateCompensateVo {

    /** 车辆VIN */
    @NotBlank(message = "vin不能为空")
    private String vin;

    /** 设备类别 */
    @NotBlank(message = "deviceCategory不能为空")
    private String deviceCategory;

    /** 设备SN */
    @NotBlank(message = "deviceSn不能为空")
    private String deviceSn;

    /** 证书Profile */
    @NotBlank(message = "certificateProfile不能为空")
    private String certificateProfile;

    /** CSR DER Base64（受信工位回读） */
    @NotBlank(message = "csrDerBase64不能为空")
    private String csrDerBase64;

    /** 业务请求ID（可选，已存在时进入幂等比对；缺省由服务端生成） */
    private String requestId;

    /** MES原请求号（人工补偿关联） */
    private String originalRequestId;

    /** 产线设备号 */
    private String facilityNo;

    /** 产线工位代码 */
    private String lineCode;

    /** 关联工单号 */
    @NotBlank(message = "ticketNo不能为空")
    private String ticketNo;

    /** 人工补偿原因 */
    @NotBlank(message = "reason不能为空")
    private String reason;
}
