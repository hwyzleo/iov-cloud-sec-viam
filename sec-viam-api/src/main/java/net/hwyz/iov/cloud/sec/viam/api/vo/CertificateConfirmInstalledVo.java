package net.hwyz.iov.cloud.sec.viam.api.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 证书安装确认请求VO（SEC-VIAM-DSN-CR-001 / FR-VIAM-002）
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CertificateConfirmInstalledVo {

    /** 业务请求ID */
    private String requestId;

    /** 安装结果：SUCCESS / FAIL */
    private String result;

    /** 失败原因（result=FAIL 时） */
    private String failReason;

    /** 车辆VIN（可选，校验匹配） */
    private String vin;

    /** 设备SN（可选，校验匹配） */
    private String deviceSn;

    /** 证书序列号（可选，校验匹配） */
    private String certSn;

    /** 人工补录原因 */
    private String reason;

    /** 关联工单号 */
    private String ticketNo;

    /** 操作人ID */
    private String operatorId;
}
