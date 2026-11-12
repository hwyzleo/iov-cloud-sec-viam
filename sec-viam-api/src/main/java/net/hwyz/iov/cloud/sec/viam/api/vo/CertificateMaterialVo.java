package net.hwyz.iov.cloud.sec.viam.api.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 证书材料VO（SEC-VIAM-DSN-CR-002 / D-VIAM-015）
 * <p>
 * 仅在受权只读端点返回，供运维手动注入设备；不落库、不缓存。
 * </p>
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CertificateMaterialVo {

    /** 业务请求ID */
    private String requestId;

    /** 证书序列号（canonical hex） */
    private String certSn;

    /** 证书SHA-256指纹 */
    private String certificateFingerprint;

    /** 叶子证书 DER Base64 */
    private String certificateDerBase64;

    /** 证书链 DER Base64（从叶子到根） */
    private String[] chainDerBase64;
}
