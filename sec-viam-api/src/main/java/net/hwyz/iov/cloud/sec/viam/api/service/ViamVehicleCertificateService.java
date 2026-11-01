package net.hwyz.iov.cloud.sec.viam.api.service;

import net.hwyz.iov.cloud.framework.common.constant.ServiceNameConstants;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamServiceConstants;
import net.hwyz.iov.cloud.sec.viam.api.fallback.ViamVehicleCertificateServiceFallbackFactory;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateApplyResultVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateApplyVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateConfirmInstalledVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateStatusVo;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;

import java.time.Instant;
import java.util.List;

/**
 * 设备证书生命周期服务 Feign 契约（SEC-VIAM-DSN-CR-001 / FR-VIAM-002）
 * <p>
 * 承接 VMD 设备证书申请/登记、安装确认、查询、对账、人工补偿和生命周期编排，
 * 沿用现行证书安全前置及审计；PKI/CA 仍负责实际签发及吊销权威。
 * </p>
 *
 * @author hwyz_leo
 */
@FeignClient(contextId = "viamVehicleCertificateService", value = ServiceNameConstants.SEC_VIAM,
        path = ViamServiceConstants.VEHICLE_CERTIFICATE_V1,
        fallbackFactory = ViamVehicleCertificateServiceFallbackFactory.class)
public interface ViamVehicleCertificateService {

    /**
     * 申请设备证书
     *
     * @param request 申请命令
     * @return 申请结果
     */
    @PostMapping("/apply")
    CertificateApplyResultVo apply(@RequestBody CertificateApplyVo request);

    /**
     * 查询证书申请状态
     *
     * @param requestId 业务请求ID
     * @return 状态结果
     */
    @GetMapping("/request/{requestId}/status")
    CertificateStatusVo status(@PathVariable("requestId") String requestId);

    /**
     * 确认证书安装
     *
     * @param request 确认命令
     */
    @PostMapping("/confirmInstalled")
    void confirmInstalled(@RequestBody CertificateConfirmInstalledVo request);

    /**
     * 按证书序列号查询证书
     *
     * @param certSn 证书序列号
     * @return 证书状态
     */
    @GetMapping("/certSn/{certSn}")
    CertificateStatusVo getByCertSn(@PathVariable("certSn") String certSn);

    /**
     * 查询更新时间大于指定时间的证书列表（对账）
     *
     * @param updatedAfter 更新时间
     * @param limit        限制数量
     * @return 证书列表
     */
    @GetMapping("/bindings/changed")
    List<CertificateStatusVo> listChanged(@RequestParam("updatedAfter") Instant updatedAfter,
                                          @RequestParam(value = "limit", defaultValue = "100") int limit);
}
