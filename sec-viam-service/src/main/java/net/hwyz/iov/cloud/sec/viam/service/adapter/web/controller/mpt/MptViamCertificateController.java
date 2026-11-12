package net.hwyz.iov.cloud.sec.viam.service.adapter.web.controller.mpt;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.framework.common.bean.ApiResponse;
import net.hwyz.iov.cloud.framework.common.bean.PageResult;
import net.hwyz.iov.cloud.framework.security.annotation.RequiresPermissions;
import net.hwyz.iov.cloud.framework.web.controller.BaseController;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateCompensateVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateDetailVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateListItemVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateMaterialVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateOperationResultVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateReconcileVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateReissueVo;
import net.hwyz.iov.cloud.sec.viam.service.application.service.CertificateProvisioningAppService;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.query.CertificateQuery;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

/**
 * 车辆设备证书管理控制器（MPT，SEC-VIAM-DSN-CR-002 / FR-VIAM-002 / D-VIAM-010）
 * <p>
 * 证书查询、人工补申请、对账、安装补录、证书本体重取与重新签发。
 * 操作人一律取当前 EIAM 认证用户，请求体不得自报；所有写操作落不可变操作审计。
 * 响应统一为 framework {@code ApiResponse}，与 VMD/CIAM 等管理面保持一致。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/mpt/viam/certificate")
public class MptViamCertificateController extends BaseController {

    private final CertificateProvisioningAppService certificateProvisioningAppService;
    private final SecurityOperatorContext operatorContext;

    /**
     * 分页查询证书申请记录（列表不含 CSR 全文与证书本体）。
     */
    @GetMapping("/list")
    @RequiresPermissions("viam:certificate:list")
    public ApiResponse<PageResult<CertificateListItemVo>> list(
            @RequestParam(value = "vin", required = false) String vin,
            @RequestParam(value = "deviceSn", required = false) String deviceSn,
            @RequestParam(value = "certSn", required = false) String certSn,
            @RequestParam(value = "requestId", required = false) String requestId,
            @RequestParam(value = "status", required = false) String status,
            @RequestParam(value = "sourceSystem", required = false) String sourceSystem,
            @RequestParam(value = "beginTime", required = false) String beginTime,
            @RequestParam(value = "endTime", required = false) String endTime) {
        log.info("MPT证书列表查询: operator={}, vin={}, status={}",
                operatorContext.operatorId(), vin, status);
        startPage();
        CertificateQuery query = new CertificateQuery(vin, deviceSn, certSn, requestId,
                status, sourceSystem, parseBegin(beginTime), parseEnd(endTime));
        return ApiResponse.ok(certificateProvisioningAppService.search(query));
    }

    /**
     * 查询证书申请详情与脱敏操作审计时间线。
     */
    @GetMapping("/request/{requestId}")
    @RequiresPermissions("viam:certificate:query")
    public ApiResponse<CertificateDetailVo> detail(@PathVariable("requestId") String requestId) {
        return ApiResponse.ok(certificateProvisioningAppService.detail(requestId));
    }

    /**
     * 人工补申请（MES 请求未达场景；CSR 必须来自受信工位回读）。
     */
    @PostMapping("/compensate")
    @RequiresPermissions("viam:certificate:compensate")
    public ApiResponse<CertificateOperationResultVo> compensate(
            @RequestBody @Valid CertificateCompensateVo request, HttpServletRequest servletRequest) {
        log.info("MPT证书人工补申请: operator={}, vin={}, deviceSn={}",
                operatorContext.operatorId(), request.getVin(), request.getDeviceSn());
        return ApiResponse.ok(certificateProvisioningAppService.compensate(request,
                operatorContext.operatorId(), operatorContext.operatorName(),
                remoteIp(servletRequest), servletRequest.getHeader("User-Agent")));
    }

    /**
     * 对已有申请继续/对账（原因与工单落审计）。
     */
    @PostMapping("/request/{requestId}/reconcile")
    @RequiresPermissions("viam:certificate:reconcile")
    public ApiResponse<CertificateOperationResultVo> reconcile(@PathVariable("requestId") String requestId,
                                                               @RequestBody(required = false) CertificateReconcileVo request,
                                                               HttpServletRequest servletRequest) {
        log.info("MPT证书对账: requestId={}, operator={}", requestId, operatorContext.operatorId());
        return ApiResponse.ok(certificateProvisioningAppService.reconcileForMpt(requestId, request,
                operatorContext.operatorId(), remoteIp(servletRequest),
                servletRequest.getHeader("User-Agent")));
    }

    /**
     * 安装结果补录（原因与工单必填；操作人服务端注入）。
     */
    @PostMapping("/request/{requestId}/confirmInstalled")
    @RequiresPermissions("viam:certificate:confirmInstalled")
    public ApiResponse<CertificateOperationResultVo> confirmInstalled(
            @PathVariable("requestId") String requestId,
            @RequestBody @Valid net.hwyz.iov.cloud.sec.viam.api.vo.CertificateConfirmInstalledVo request,
            HttpServletRequest servletRequest) {
        log.info("MPT证书安装补录: requestId={}, result={}, operator={}",
                requestId, request.getResult(), operatorContext.operatorId());
        // requestId 以路径为准；operatorId 一律服务端覆盖，忽略请求体自报值
        request.setRequestId(requestId);
        request.setOperatorId(operatorContext.operatorId());
        return ApiResponse.ok(certificateProvisioningAppService.confirmInstalled(request,
                operatorContext.operatorId(), remoteIp(servletRequest),
                servletRequest.getHeader("User-Agent")));
    }

    /**
     * 获取已签发证书本体（只读；不落库、不缓存、不落审计不返回）。
     */
    @GetMapping("/request/{requestId}/certificate")
    @RequiresPermissions("viam:certificate:query")
    public ResponseEntity<ApiResponse<CertificateMaterialVo>> certificate(
            @PathVariable("requestId") String requestId, HttpServletRequest servletRequest) {
        log.info("MPT获取证书本体: requestId={}, operator={}", requestId, operatorContext.operatorId());
        CertificateMaterialVo material = certificateProvisioningAppService.queryCertificateMaterial(
                requestId, operatorContext.operatorId(),
                remoteIp(servletRequest), servletRequest.getHeader("User-Agent"));
        return ResponseEntity.ok()
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .header(HttpHeaders.PRAGMA, "no-cache")
                .body(ApiResponse.ok(material));
    }

    /**
     * 重新签发/续期（新 CSR；旧证进入 SUPERSEDED 终态，新记录独立 requestId）。
     */
    @PostMapping("/request/{requestId}/reissue")
    @RequiresPermissions("viam:certificate:reissue")
    public ApiResponse<CertificateOperationResultVo> reissue(@PathVariable("requestId") String requestId,
                                                             @RequestBody @Valid CertificateReissueVo request,
                                                             HttpServletRequest servletRequest) {
        log.info("MPT证书重新签发: oldRequestId={}, operator={}", requestId, operatorContext.operatorId());
        return ApiResponse.ok(certificateProvisioningAppService.reissue(requestId, request,
                operatorContext.operatorId(), remoteIp(servletRequest),
                servletRequest.getHeader("User-Agent")));
    }

    /**
     * 客户端IP（代理头回退）。
     */
    private static String remoteIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isBlank() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("X-Real-IP");
        }
        if (ip == null || ip.isBlank()) {
            ip = request.getRemoteAddr();
        }
        return ip != null && ip.contains(",") ? ip.split(",")[0].trim() : ip;
    }

    /**
     * 起始时间：支持 yyyy-MM-dd（取当日 00:00:00Z）与 ISO-8601 Instant。
     */
    private static Instant parseBegin(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String text = value.trim();
        if (text.length() == 10) {
            return LocalDate.parse(text).atStartOfDay().toInstant(ZoneOffset.UTC);
        }
        try {
            return Instant.parse(text);
        } catch (Exception ignored) {
            return LocalDateTime.parse(text).toInstant(ZoneOffset.UTC);
        }
    }

    /**
     * 结束时间：支持 yyyy-MM-dd（取当日 23:59:59Z）与 ISO-8601 Instant。
     */
    private static Instant parseEnd(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String text = value.trim();
        if (text.length() == 10) {
            return LocalDate.parse(text).atTime(23, 59, 59).toInstant(ZoneOffset.UTC);
        }
        try {
            return Instant.parse(text);
        } catch (Exception ignored) {
            return LocalDateTime.parse(text).toInstant(ZoneOffset.UTC);
        }
    }
}
