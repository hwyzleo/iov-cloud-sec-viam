package net.hwyz.iov.cloud.sec.viam.service.adapter.web.controller.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.sec.viam.api.service.ViamKeyProvisioningService;
import net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamKeyProvisioningAckRequest;
import net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamKeyProvisioningAckResult;
import net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamKeyProvisioningRequest;
import net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamKeyProvisioningResponse;
import net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamKeyProvisioningStatusRequest;
import net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamKeyProvisioningStatusResponse;
import net.hwyz.iov.cloud.sec.viam.service.application.service.KeyProvisioningApplicationFacade;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 官方 Keyprov Service 端点实现（SEC-VIAM-DSN-CR-001 / FR-VIAM-003）
 * <p>
 * 实现 sec-viam-api 单点发布的 {@link ViamKeyProvisioningService}，仅做委派；
 * request/ack/status 相对路径保持（服务发现指向 VIAM）。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping(ViamKeyProvisioningService.BASE_PATH)
@ConditionalOnProperty(name = "viam.crypto.provisioning.enabled", havingValue = "true")
public class KeyProvisioningServiceController implements ViamKeyProvisioningService {

    private final KeyProvisioningApplicationFacade keyProvisioningApplicationFacade;

    @Override
    @PostMapping("/request")
    public ViamKeyProvisioningResponse request(@RequestBody ViamKeyProvisioningRequest request) {
        log.info("VIAM Keyprov官方服务请求: hasContext={}", request != null && request.getDeviceContext() != null);
        return keyProvisioningApplicationFacade.request(request);
    }

    @Override
    @PostMapping("/ack")
    public ViamKeyProvisioningAckResult ack(@RequestBody ViamKeyProvisioningAckRequest request) {
        log.info("VIAM Keyprov官方服务ACK: hasContext={}", request != null && request.getDeviceContext() != null);
        return keyProvisioningApplicationFacade.ack(request);
    }

    @Override
    @PostMapping("/status")
    public ViamKeyProvisioningStatusResponse status(@RequestBody ViamKeyProvisioningStatusRequest request) {
        log.info("VIAM Keyprov官方服务状态查询: hasContext={}", request != null && request.getDeviceContext() != null);
        return keyProvisioningApplicationFacade.status(request);
    }
}
