package net.hwyz.iov.cloud.sec.viam.api.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import jakarta.validation.constraints.NotBlank;
import java.time.Instant;

/**
 * 设备接入准入裁决请求VO（SEC-VIAM-DSN-CR-001 / FR-VIAM-004）
 * <p>
 * uid、certSerial、certFingerprint、leafCertificateDer 对所有设备准入请求均必填；
 * leafCertificateDer 为本次 EMQX mTLS 实际叶子证书的标准 Base64 编码 DER，解码后最大 8 KiB，
 * 仅用于本次裁决，VIAM 不落库、不进入审计正文或普通日志。
 * </p>
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DeviceAdmissionCheckVo {

    /** 设备接入身份（证书 CN = HSM UID） */
    @NotBlank(message = "设备UID不能为空")
    private String uid;

    /** 证书序列号（provider canonical form） */
    @NotBlank(message = "证书序列号不能为空")
    private String certSerial;

    /** 证书 SHA-256 指纹（小写十六进制，可含冒号分隔） */
    @NotBlank(message = "证书指纹不能为空")
    private String certFingerprint;

    /** 本次 mTLS 实际叶子证书（标准 Base64 编码 DER，≤8 KiB） */
    @NotBlank(message = "叶子证书不能为空")
    private String leafCertificateDer;

    /** MQTT 客户端 ID（可选） */
    private String clientId;

    /** 来源 IP（可选，仅用于审计摘要） */
    private String sourceIp;

    /** 请求时刻（可选） */
    private Instant ts;
}
