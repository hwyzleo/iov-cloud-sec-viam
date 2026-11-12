package net.hwyz.iov.cloud.sec.viam.api.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 证书对账请求VO（SEC-VIAM-DSN-CR-002 / FR-VIAM-002）
 * <p>
 * 仅对 PENDING_RECONCILE / FAILED / ISSUING 生效；无 pkiRequestId 且无 CSR 时拒绝自动推进。
 * </p>
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CertificateReconcileVo {

    /** 人工对账原因 */
    private String reason;

    /** 关联工单号 */
    private String ticketNo;

    /** CSR DER Base64（FAILED 重试时可选；由受信工位回读） */
    private String csrDerBase64;
}
