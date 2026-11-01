package net.hwyz.iov.cloud.sec.viam.api.fallback;

import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.sec.viam.api.service.ViamVehicleCertificateService;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateApplyResultVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateApplyVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateConfirmInstalledVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateStatusVo;
import org.springframework.cloud.openfeign.FallbackFactory;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;

/**
 * 设备证书生命周期 Feign 降级工厂（SEC-VIAM-DSN-CR-001 / FR-VIAM-002）
 * <p>
 * 证书域依赖不可用时明确不可用，不返回伪成功。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
public class ViamVehicleCertificateServiceFallbackFactory implements FallbackFactory<ViamVehicleCertificateService> {

    @Override
    public ViamVehicleCertificateService create(Throwable cause) {
        log.warn("VIAM证书生命周期服务不可用: {}", cause.getMessage());
        return new ViamVehicleCertificateService() {
            @Override
            public CertificateApplyResultVo apply(CertificateApplyVo request) {
                throw new IllegalStateException("VIAM证书服务不可用，无法申请");
            }

            @Override
            public CertificateStatusVo status(String requestId) {
                throw new IllegalStateException("VIAM证书服务不可用，无法查询状态");
            }

            @Override
            public void confirmInstalled(CertificateConfirmInstalledVo request) {
                throw new IllegalStateException("VIAM证书服务不可用，无法确认安装");
            }

            @Override
            public CertificateStatusVo getByCertSn(String certSn) {
                throw new IllegalStateException("VIAM证书服务不可用，无法查询");
            }

            @Override
            public List<CertificateStatusVo> listChanged(Instant updatedAfter, int limit) {
                throw new IllegalStateException("VIAM证书服务不可用，无法对账");
            }
        };
    }
}
