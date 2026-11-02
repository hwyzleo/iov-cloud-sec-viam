package net.hwyz.iov.cloud.sec.viam.service.adapter.web.controller.mpt;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.framework.security.annotation.RequiresPermissions;
import net.hwyz.iov.cloud.framework.security.util.SecurityUtils;
import net.hwyz.iov.cloud.framework.web.controller.BaseController;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateApplyResultVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateConfirmInstalledVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateStatusVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.DeviceLoginRecordVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.DeviceOnboardingVo;
import net.hwyz.iov.cloud.sec.viam.service.application.service.BusinessKeyMaintenanceAppService;
import net.hwyz.iov.cloud.sec.viam.service.application.service.CertificateProvisioningAppService;
import net.hwyz.iov.cloud.sec.viam.service.application.service.DeviceSecurityTimelineAppService;
import net.hwyz.iov.cloud.sec.viam.service.application.service.accessinvalidation.AccessInvalidationAppService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * VIAM MPT 管理控制器（SEC-VIAM-DSN-CR-001 / FR-VIAM-002/003/007 / D-VIAM-009 / G-4）
 * <p>
 * 证书人工补偿/对账、业务密钥轮换/吊销/清阻断、安全时间线查询。
 * 安全事实不可人工改写（无人工改登录时间、无假成功）。
 * 操作人取当前 EIAM 认证用户（{@link SecurityUtils#getUserId()}），禁止自报；
 * 安全写端点以 {@link RequiresPermissions} 强制权限（viam:* 权限由 MPT 侧授予）。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/mpt/viam")
public class MptViamAdminController extends BaseController {

    private final CertificateProvisioningAppService certificateProvisioningAppService;
    private final BusinessKeyMaintenanceAppService businessKeyMaintenanceAppService;
    private final DeviceSecurityTimelineAppService timelineAppService;
    private final AccessInvalidationAppService accessInvalidationAppService;

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
    @RequiresPermissions("viam:certificate:reconcile")
    @PostMapping("/certificate/reconcile")
    public CertificateApplyResultVo reconcile(@RequestParam("requestId") String requestId,
                                              @RequestParam(value = "csrDerBase64", required = false) String csrDerBase64) {
        log.info("MPT证书对账: requestId={}, operator={}", requestId, safeUserId());
        return certificateProvisioningAppService.reconcile(requestId, csrDerBase64);
    }

    /**
     * 人工确认安装（补录）。
     */
    @RequiresPermissions("viam:certificate:confirmInstalled")
    @PostMapping("/certificate/confirmInstalled")
    public void confirmInstalled(@RequestBody CertificateConfirmInstalledVo request) {
        certificateProvisioningAppService.confirmInstalled(request);
    }

    // ================= 业务密钥域 =================

    /**
     * 轮换（旧材料降级，不重派生）。
     */
    @RequiresPermissions("viam:businessKey:rotate")
    @PostMapping("/businessKey/rotate")
    public void rotate(@RequestParam("deviceSn") String deviceSn,
                       @RequestParam("businessDomain") String businessDomain,
                       @RequestParam("purpose") String purpose) {
        businessKeyMaintenanceAppService.rotate(deviceSn, businessDomain, purpose, safeUserId());
    }

    /**
     * 吊销（终态）。
     */
    @RequiresPermissions("viam:businessKey:revoke")
    @PostMapping("/businessKey/revoke")
    public void revoke(@RequestParam("deviceSn") String deviceSn,
                       @RequestParam("businessDomain") String businessDomain,
                       @RequestParam("purpose") String purpose) {
        businessKeyMaintenanceAppService.revoke(deviceSn, businessDomain, purpose, safeUserId());
    }

    /**
     * 清阻断（仅解除状态阻断，不重派生）。
     */
    @RequiresPermissions("viam:businessKey:clearBlocking")
    @PostMapping("/businessKey/clearBlocking")
    public void clearBlocking(@RequestParam("deviceSn") String deviceSn,
                              @RequestParam("businessDomain") String businessDomain,
                              @RequestParam("purpose") String purpose) {
        businessKeyMaintenanceAppService.clearBlocking(deviceSn, businessDomain, purpose, safeUserId());
    }

    // ================= 访问失效 / 安全状态（FR-VIAM-008 / T05 / G-3） =================

    /**
     * 安全封禁（触发 VAGW 失效：ACL/缓存失效 + 实际断连；生效时限内必须执行）。
     */
    @RequiresPermissions("viam:principal:block")
    @PostMapping("/principal/block")
    public void block(@RequestParam("principalId") String principalId,
                      @RequestParam("reason") String reason) {
        accessInvalidationAppService.block(principalId, reason, safeUserId(), "MPT_ADMIN");
    }

    /**
     * 解除封禁（仅恢复重新认证资格，不复活旧 ACL/旧会话）。
     */
    @RequiresPermissions("viam:principal:unblock")
    @PostMapping("/principal/unblock")
    public void unblock(@RequestParam("principalId") String principalId) {
        accessInvalidationAppService.unblock(principalId, safeUserId(), "MPT_ADMIN");
    }

    /**
     * 退役（终态，触发 VAGW 失效）。
     */
    @RequiresPermissions("viam:principal:retire")
    @PostMapping("/principal/retire")
    public void retire(@RequestParam("principalId") String principalId,
                       @RequestParam("reason") String reason) {
        accessInvalidationAppService.retire(principalId, reason, safeUserId(), "MPT_ADMIN");
    }

    // ================= 安全时间线（FR-VIAM-007 / D-VIAM-009） =================

    /**
     * 按成功接入记录ID查询（安全时间线）。
     */
    @GetMapping("/timeline/login/{loginId}")
    public DeviceLoginRecordVo getLoginRecord(@PathVariable("loginId") String loginId) {
        return timelineAppService.getLoginRecord(loginId);
    }

    /**
     * 按主体ID查询安全开通状态。
     */
    @GetMapping("/timeline/onboarding/{principalId}")
    public DeviceOnboardingVo getOnboarding(@PathVariable("principalId") String principalId) {
        return timelineAppService.getOnboardingByPrincipalId(principalId);
    }

    /**
     * 当前认证操作人（EIAM 用户ID）；未认证时为空，由应用服务 fail-closed。
     */
    private String safeUserId() {
        try {
            Long userId = SecurityUtils.getUserId();
            return userId != null ? String.valueOf(userId) : null;
        } catch (Exception e) {
            return null;
        }
    }
}
