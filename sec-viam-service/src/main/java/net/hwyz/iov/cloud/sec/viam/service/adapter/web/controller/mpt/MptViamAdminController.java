package net.hwyz.iov.cloud.sec.viam.service.adapter.web.controller.mpt;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.framework.common.bean.ApiResponse;
import net.hwyz.iov.cloud.framework.security.annotation.RequiresPermissions;
import net.hwyz.iov.cloud.framework.web.controller.BaseController;
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
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * VIAM MPT 管理控制器（SEC-VIAM-DSN-CR-001 / FR-VIAM-002/003/007 / D-VIAM-009 / G-4）
 * <p>
 * 保留：证书状态查询、业务密钥目录行维护（rotate/revoke/clearBlocking）、
 * 安全封禁/解封/退役、安全时间线查询。
 * 已迁出（SEC-VIAM-DSN-CR-002）：证书对账/安装补录 → {@link MptViamCertificateController}；
 * 开通批次治理 → {@link MptViamBusinessKeyGovernanceController}。
 * 安全事实不可人工改写（无人工改登录时间、无假成功）。
 * 操作人取当前 EIAM 认证用户（{@link SecurityOperatorContext}），禁止自报；
 * 安全写端点以 {@link RequiresPermissions} 强制权限（viam:* 权限由 MPT 侧授予）。
 * 响应统一为 framework {@code ApiResponse}，与 VMD/CIAM 等管理面保持一致。
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
    private final SecurityOperatorContext operatorContext;

    // ================= 证书域（只读状态查询；写操作见 MptViamCertificateController） =================

    /**
     * 查询证书申请状态（对账入口）。
     */
    @GetMapping("/certificate/request/{requestId}/status")
    @RequiresPermissions("viam:certificate:query")
    public ApiResponse<CertificateStatusVo> certificateStatus(@PathVariable("requestId") String requestId) {
        return ApiResponse.ok(certificateProvisioningAppService.status(requestId));
    }

    // ================= 业务密钥目录行维护 =================

    /**
     * 轮换（旧材料降级，不重派生）。
     */
    @RequiresPermissions("viam:businessKey:rotate")
    @PostMapping("/businessKey/rotate")
    public ApiResponse<Void> rotate(@RequestParam("deviceSn") String deviceSn,
                                    @RequestParam("businessDomain") String businessDomain,
                                    @RequestParam("purpose") String purpose) {
        businessKeyMaintenanceAppService.rotate(deviceSn, businessDomain, purpose, operatorContext.operatorId());
        return ApiResponse.ok();
    }

    /**
     * 吊销（终态）。
     */
    @RequiresPermissions("viam:businessKey:revoke")
    @PostMapping("/businessKey/revoke")
    public ApiResponse<Void> revoke(@RequestParam("deviceSn") String deviceSn,
                                    @RequestParam("businessDomain") String businessDomain,
                                    @RequestParam("purpose") String purpose) {
        businessKeyMaintenanceAppService.revoke(deviceSn, businessDomain, purpose, operatorContext.operatorId());
        return ApiResponse.ok();
    }

    /**
     * 清阻断（仅目录行：解除状态阻断，不重派生）。
     * <p>
     * 批次级清阻断见 {@link MptViamBusinessKeyGovernanceController#clearBlocking}。
     * </p>
     */
    @RequiresPermissions("viam:businessKey:clearBlocking")
    @PostMapping("/businessKey/clearBlocking")
    public ApiResponse<Void> clearBlocking(@RequestParam("deviceSn") String deviceSn,
                                           @RequestParam("businessDomain") String businessDomain,
                                           @RequestParam("purpose") String purpose) {
        businessKeyMaintenanceAppService.clearBlocking(deviceSn, businessDomain, purpose,
                operatorContext.operatorId());
        return ApiResponse.ok();
    }

    // ================= 访问失效 / 安全状态（FR-VIAM-008 / T05 / G-3） =================

    /**
     * 安全封禁（触发 VAGW 失效：ACL/缓存失效 + 实际断连；生效时限内必须执行）。
     */
    @RequiresPermissions("viam:principal:block")
    @PostMapping("/principal/block")
    public ApiResponse<Void> block(@RequestParam("principalId") String principalId,
                                   @RequestParam("reason") String reason) {
        accessInvalidationAppService.block(principalId, reason, operatorContext.operatorId(), "MPT_ADMIN");
        return ApiResponse.ok();
    }

    /**
     * 解除封禁（仅恢复重新认证资格，不复活旧 ACL/旧会话）。
     */
    @RequiresPermissions("viam:principal:unblock")
    @PostMapping("/principal/unblock")
    public ApiResponse<Void> unblock(@RequestParam("principalId") String principalId) {
        accessInvalidationAppService.unblock(principalId, operatorContext.operatorId(), "MPT_ADMIN");
        return ApiResponse.ok();
    }

    /**
     * 退役（终态，触发 VAGW 失效）。
     */
    @RequiresPermissions("viam:principal:retire")
    @PostMapping("/principal/retire")
    public ApiResponse<Void> retire(@RequestParam("principalId") String principalId,
                                    @RequestParam("reason") String reason) {
        accessInvalidationAppService.retire(principalId, reason, operatorContext.operatorId(), "MPT_ADMIN");
        return ApiResponse.ok();
    }

    // ================= 安全时间线（FR-VIAM-007 / D-VIAM-009） =================

    /**
     * 按成功接入记录ID查询（安全时间线）。
     */
    @GetMapping("/timeline/login/{loginId}")
    public ApiResponse<DeviceLoginRecordVo> getLoginRecord(@PathVariable("loginId") String loginId) {
        return ApiResponse.ok(timelineAppService.getLoginRecord(loginId));
    }

    /**
     * 按主体ID查询安全开通状态。
     */
    @GetMapping("/timeline/onboarding/{principalId}")
    public ApiResponse<DeviceOnboardingVo> getOnboarding(@PathVariable("principalId") String principalId) {
        return ApiResponse.ok(timelineAppService.getOnboardingByPrincipalId(principalId));
    }
}
