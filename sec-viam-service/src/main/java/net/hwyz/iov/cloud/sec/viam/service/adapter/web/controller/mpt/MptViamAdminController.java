package net.hwyz.iov.cloud.sec.viam.service.adapter.web.controller.mpt;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateApplyResultVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateConfirmInstalledVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateStatusVo;
import net.hwyz.iov.cloud.sec.viam.service.application.service.BusinessKeyMaintenanceAppService;
import net.hwyz.iov.cloud.sec.viam.service.application.service.CertificateProvisioningAppService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * VIAM MPT 管理控制器（SEC-VIAM-DSN-CR-001 / FR-VIAM-002/003/007 / D-VIAM-009）
 * <p>
 * 证书人工补偿/对账、业务密钥轮换/吊销/清阻断、安全时间线查询。
 * 安全事实不可人工改写（无人工改登录时间、无假成功）。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/mpt/viam")
public class MptViamAdminController {

    private final CertificateProvisioningAppService certificateProvisioningAppService;
    private final BusinessKeyMaintenanceAppService businessKeyMaintenanceAppService;

    // ================= 证书域 =================

    /**
     * 查询证书申请状态（对账入口）。
     */
    @GetMapping("/certificate/request/{requestId}/status")
    public CertificateStatusVo certificateStatus(@PathVariable("requestId") String requestId) {
        return certificateProvisioningAppService.status(requestId);
    }

    /**
     * 人工补偿/对账证书申请（PENDING_RECONCILE/FAILED）。
     */
    @PostMapping("/certificate/reconcile")
    public CertificateApplyResultVo reconcile(@RequestParam("requestId") String requestId,
                                              @RequestParam(value = "csrDerBase64", required = false) String csrDerBase64) {
        log.info("MPT证书对账: requestId={}", requestId);
        return certificateProvisioningAppService.reconcile(requestId, csrDerBase64);
    }

    /**
     * 人工确认安装（补录）。
     */
    @PostMapping("/certificate/confirmInstalled")
    public void confirmInstalled(@RequestBody CertificateConfirmInstalledVo request) {
        certificateProvisioningAppService.confirmInstalled(request);
    }

    // ================= 业务密钥域 =================

    /**
     * 轮换（旧材料降级，不重派生）。
     */
    @PostMapping("/businessKey/rotate")
    public void rotate(@RequestParam("deviceSn") String deviceSn,
                       @RequestParam("businessDomain") String businessDomain,
                       @RequestParam("purpose") String purpose,
                       @RequestParam(value = "operatorId", required = false) String operatorId) {
        businessKeyMaintenanceAppService.rotate(deviceSn, businessDomain, purpose, operatorId);
    }

    /**
     * 吊销（终态）。
     */
    @PostMapping("/businessKey/revoke")
    public void revoke(@RequestParam("deviceSn") String deviceSn,
                       @RequestParam("businessDomain") String businessDomain,
                       @RequestParam("purpose") String purpose,
                       @RequestParam(value = "operatorId", required = false) String operatorId) {
        businessKeyMaintenanceAppService.revoke(deviceSn, businessDomain, purpose, operatorId);
    }

    /**
     * 清阻断（仅解除状态阻断，不重派生）。
     */
    @PostMapping("/businessKey/clearBlocking")
    public void clearBlocking(@RequestParam("deviceSn") String deviceSn,
                              @RequestParam("businessDomain") String businessDomain,
                              @RequestParam("purpose") String purpose,
                              @RequestParam(value = "operatorId", required = false) String operatorId) {
        businessKeyMaintenanceAppService.clearBlocking(deviceSn, businessDomain, purpose, operatorId);
    }
}
