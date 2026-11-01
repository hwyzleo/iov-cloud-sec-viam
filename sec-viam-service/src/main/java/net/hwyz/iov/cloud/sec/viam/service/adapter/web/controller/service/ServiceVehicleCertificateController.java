package net.hwyz.iov.cloud.sec.viam.service.adapter.web.controller.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamServiceConstants;
import net.hwyz.iov.cloud.sec.viam.api.service.ViamVehicleCertificateService;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateApplyResultVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateApplyVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateConfirmInstalledVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateStatusVo;
import net.hwyz.iov.cloud.sec.viam.service.application.service.CertificateProvisioningAppService;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;

/**
 * 设备证书生命周期控制器（SEC-VIAM-DSN-CR-001 / FR-VIAM-002）
 *
 * @author hwyz_leo
 */
@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping(ViamServiceConstants.VEHICLE_CERTIFICATE_V1)
public class ServiceVehicleCertificateController implements ViamVehicleCertificateService {

    private final CertificateProvisioningAppService certificateProvisioningAppService;

    @Override
    @PostMapping("/apply")
    public CertificateApplyResultVo apply(@RequestBody @Validated CertificateApplyVo request) {
        log.info("VIAM证书申请: requestId={}, vin={}", request.getRequestId(), request.getVin());
        return certificateProvisioningAppService.apply(request);
    }

    @Override
    @GetMapping("/request/{requestId}/status")
    public CertificateStatusVo status(@PathVariable("requestId") String requestId) {
        return certificateProvisioningAppService.status(requestId);
    }

    @Override
    @PostMapping("/confirmInstalled")
    public void confirmInstalled(@RequestBody @Validated CertificateConfirmInstalledVo request) {
        certificateProvisioningAppService.confirmInstalled(request);
    }

    @Override
    @GetMapping("/certSn/{certSn}")
    public CertificateStatusVo getByCertSn(@PathVariable("certSn") String certSn) {
        return certificateProvisioningAppService.getByCertSn(certSn);
    }

    @Override
    @GetMapping("/bindings/changed")
    public List<CertificateStatusVo> listChanged(@RequestParam("updatedAfter") Instant updatedAfter,
                                                 @RequestParam(value = "limit", defaultValue = "100") int limit) {
        return certificateProvisioningAppService.listChanged(updatedAfter, limit);
    }
}
