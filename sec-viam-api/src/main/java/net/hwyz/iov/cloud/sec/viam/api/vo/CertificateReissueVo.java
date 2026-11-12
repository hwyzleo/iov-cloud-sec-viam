package net.hwyz.iov.cloud.sec.viam.api.vo;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 证书重新签发/续期请求VO（SEC-VIAM-DSN-CR-002 / D-VIAM-016）
 * <p>
 * CSR 必须由设备侧重新提供（同公钥续期 / 新公钥换钥）；后台不生成密钥或 CSR。
 * 重签产生新的申请记录，旧记录进入 SUPERSEDED 终态，不复用旧 requestId。
 * </p>
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CertificateReissueVo {

    /** 新 CSR DER Base64 */
    @NotBlank(message = "csrDerBase64不能为空")
    private String csrDerBase64;

    /** 重签原因 */
    @NotBlank(message = "reason不能为空")
    private String reason;

    /** 关联工单号 */
    @NotBlank(message = "ticketNo不能为空")
    private String ticketNo;

    /** 新申请 requestId（可选幂等键；缺省由服务端生成） */
    private String requestId;
}
