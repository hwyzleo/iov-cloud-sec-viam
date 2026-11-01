package net.hwyz.iov.cloud.sec.viam.api.service;

import net.hwyz.iov.cloud.framework.common.constant.ServiceNameConstants;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamServiceConstants;
import net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamKeyProvisioningAckRequest;
import net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamKeyProvisioningAckResult;
import net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamKeyProvisioningRequest;
import net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamKeyProvisioningResponse;
import net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamKeyProvisioningStatusRequest;
import net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamKeyProvisioningStatusResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

/**
 * 官方 Keyprov Service Feign 契约（SEC-VIAM-DSN-CR-001 / FR-VIAM-003）
 * <p>
 * VIAM 在 sec-viam-api 单点发布并唯一维护本契约，VAGW 只升级并引用已发布 artifact，
 * 不得复制第二套 Feign/DTO。request/ack/status 相对路径保持（服务发现指向 VIAM）。
 * 本契约不提供 fallback：依赖不可用时由 VAGW 侧专属熔断/超时治理，
 * 并以原 requestId 通过 /status 对账，避免误建第二批次。
 * </p>
 *
 * @author hwyz_leo
 */
@FeignClient(contextId = "viamKeyProvisioningService", value = ServiceNameConstants.SEC_VIAM,
        path = ViamKeyProvisioningService.BASE_PATH)
public interface ViamKeyProvisioningService {

    /** 官方 Keyprov Service 基础路径（实现方与调用方均引用本常量） */
    String BASE_PATH = ViamServiceConstants.KEY_PROVISIONING_V1;

    /**
     * 业务密钥开通申请。
     *
     * @param request 可信设备上下文 + canonical KeyProvisioningRequest bytes
     * @return canonical KeyProvisioningResponse 或稳定 702xxx 错误
     */
    @PostMapping("/request")
    ViamKeyProvisioningResponse request(@RequestBody ViamKeyProvisioningRequest request);

    /**
     * 设备导入 ACK。
     *
     * @param request 可信设备上下文 + canonical KeyProvisioningAck bytes
     * @return canonical KeyProvisioningAckResult 或稳定 702xxx 错误
     */
    @PostMapping("/ack")
    ViamKeyProvisioningAckResult ack(@RequestBody ViamKeyProvisioningAckRequest request);

    /**
     * 按原 requestId 查询开通状态（只读，不创建版本、不重放请求）。
     *
     * @param request 可信设备上下文 + canonical KeyProvisioningStatusRequest bytes
     * @return canonical KeyProvisioningStatusResponse 或稳定 702xxx 错误
     */
    @PostMapping("/status")
    ViamKeyProvisioningStatusResponse status(@RequestBody ViamKeyProvisioningStatusRequest request);
}
