package net.hwyz.iov.cloud.sec.viam.api.service;

import net.hwyz.iov.cloud.framework.common.constant.ServiceNameConstants;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamServiceConstants;
import net.hwyz.iov.cloud.sec.viam.api.vo.AccessInvalidationReceiptVo;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

/**
 * 官方访问失效执行回执服务（SEC-VIAM-DSN-CR-001 / FR-VIAM-008 / G-3）
 * <p>
 * VAGW 执行缓存/ACL 失效与实际断连后，以官方契约回执执行结果（含区分状态），
 * VIAM 据此推进执行跟踪状态（ACKNOWLEDGED/TIMEOUT/RECONCILED）与超时告警/对账。
 * </p>
 *
 * @author hwyz_leo
 */
@FeignClient(contextId = "viamAccessInvalidationService", value = ServiceNameConstants.SEC_VIAM,
        path = ViamAccessInvalidationService.BASE_PATH)
public interface ViamAccessInvalidationService {

    /** 基础路径（实现方与调用方均引用本常量） */
    String BASE_PATH = ViamServiceConstants.ACCESS_INVALIDATION_V1;

    /**
     * 提交失效执行回执。
     *
     * @param receipt 执行回执（invalidationId + 回执状态 + 明细）
     */
    @PostMapping("/receipt")
    void receipt(@RequestBody AccessInvalidationReceiptVo receipt);
}
