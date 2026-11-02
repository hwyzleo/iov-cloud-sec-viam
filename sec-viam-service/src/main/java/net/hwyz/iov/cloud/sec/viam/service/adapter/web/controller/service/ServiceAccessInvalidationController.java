package net.hwyz.iov.cloud.sec.viam.service.adapter.web.controller.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.sec.viam.api.service.ViamAccessInvalidationService;
import net.hwyz.iov.cloud.sec.viam.api.vo.AccessInvalidationReceiptVo;
import net.hwyz.iov.cloud.sec.viam.service.application.service.accessinvalidation.AccessInvalidationReceiptService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 访问失效执行回执控制器（SEC-VIAM-DSN-CR-001 / FR-VIAM-008 / G-3）
 * <p>
 * VAGW 执行后经官方契约回执；身份由 {@link net.hwyz.iov.cloud.sec.viam.service.adapter.web.security.ServiceIdentityInterceptor}
 * 验签（/api/service/** 强制）。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping(ViamAccessInvalidationService.BASE_PATH)
public class ServiceAccessInvalidationController implements ViamAccessInvalidationService {

    private final AccessInvalidationReceiptService receiptService;

    @Override
    @PostMapping("/receipt")
    public void receipt(@RequestBody AccessInvalidationReceiptVo receipt) {
        log.info("VIAM访问失效执行回执: invalidationId={}, state={}",
                receipt == null ? null : receipt.getInvalidationId(),
                receipt == null ? null : receipt.getReceiptState());
        receiptService.handleReceipt(receipt);
    }
}
