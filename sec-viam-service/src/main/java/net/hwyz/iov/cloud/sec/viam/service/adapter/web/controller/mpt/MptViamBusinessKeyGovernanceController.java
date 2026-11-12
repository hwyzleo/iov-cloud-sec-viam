package net.hwyz.iov.cloud.sec.viam.service.adapter.web.controller.mpt;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.framework.common.bean.ApiResponse;
import net.hwyz.iov.cloud.framework.security.annotation.RequiresPermissions;
import net.hwyz.iov.cloud.framework.web.controller.BaseController;
import net.hwyz.iov.cloud.sec.viam.api.vo.ProvisioningBatchVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.ProvisioningClearBlockingVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.ProvisioningDiagnosisVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.ProvisioningOperationResultVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.ProvisioningResolveVo;
import net.hwyz.iov.cloud.sec.viam.service.application.service.BusinessKeyGovernanceQueryAppService;
import net.hwyz.iov.cloud.sec.viam.service.application.service.BusinessKeyProvisioningGovernanceAppService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 业务密钥批次治理控制器（MPT，SEC-VIAM-DSN-CR-002 / FR-VIAM-003 / D-VIAM-017 / D-VIAM-018）
 * <p>
 * 只读：按批次 requestId 查询、证书申请 requestId 桥接、阻塞诊断（均脱敏）；
 * 破坏性：批次级一键清阻断（期望状态/版本门禁 + 幂等键）。
 * 与既有 {@code /businessKey/{rotate,revoke,clearBlocking}} 的对象不同：
 * 后者维护目录行，本控制器维护开通批次。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/mpt/viam/businessKey")
public class MptViamBusinessKeyGovernanceController extends BaseController {

    private final BusinessKeyGovernanceQueryAppService governanceQueryAppService;
    private final BusinessKeyProvisioningGovernanceAppService governanceAppService;
    private final SecurityOperatorContext operatorContext;

    /**
     * 按开通批次 requestId 查询批次状态与用途明细。
     */
    @PostMapping("/provisioningQuery")
    @RequiresPermissions("viam:businessKey:provisioning:query")
    public ApiResponse<ProvisioningBatchVo> provisioningQuery(@RequestBody Map<String, String> request) {
        String requestId = request == null ? null : request.get("requestId");
        log.info("MPT开通批次查询: requestId={}, operator={}", requestId, operatorContext.operatorId());
        return ApiResponse.ok(governanceQueryAppService.batch(requestId));
    }

    /**
     * 证书申请 requestId → 开通批次 requestId 只读桥接。
     */
    @GetMapping("/provisioning/by-certificate-request/{certificateRequestId}")
    @RequiresPermissions("viam:businessKey:provisioning:query")
    public ApiResponse<ProvisioningResolveVo> resolveByCertificateRequest(
            @PathVariable("certificateRequestId") String certificateRequestId,
            @RequestParam(value = "businessDomain", required = false) String businessDomain,
            @RequestParam(value = "includeTerminal", required = false, defaultValue = "false") boolean includeTerminal) {
        log.info("MPT证书申请→开通批次桥接: certificateRequestId={}, operator={}",
                certificateRequestId, operatorContext.operatorId());
        return ApiResponse.ok(governanceQueryAppService.resolveByCertificateRequest(
                certificateRequestId, businessDomain, includeTerminal));
    }

    /**
     * 批次阻塞诊断（只读、脱敏、不改状态）。
     */
    @GetMapping("/provisioning/{requestId}/blocking-diagnosis")
    @RequiresPermissions("viam:businessKey:diagnosis")
    public ApiResponse<ProvisioningDiagnosisVo> blockingDiagnosis(@PathVariable("requestId") String requestId) {
        log.info("MPT批次阻塞诊断: requestId={}, operator={}", requestId, operatorContext.operatorId());
        return ApiResponse.ok(governanceQueryAppService.diagnosis(requestId));
    }

    /**
     * 批次级一键清阻断（唯一破坏性入口；服务端重做全部门禁）。
     */
    @PostMapping("/provisioning/{requestId}/clear-blocking")
    @RequiresPermissions("viam:businessKey:clearBlocking")
    public ApiResponse<ProvisioningOperationResultVo> clearBlocking(
            @PathVariable("requestId") String requestId,
            @RequestBody @Valid ProvisioningClearBlockingVo request) {
        log.info("MPT批次清阻断: requestId={}, maintenanceRequestId={}, operator={}",
                requestId, request.getMaintenanceRequestId(), operatorContext.operatorId());
        return ApiResponse.ok(governanceAppService.clearBlocking(requestId, request,
                operatorContext.operatorId(), operatorContext.operatorName()));
    }
}
