package net.hwyz.iov.cloud.sec.viam.service.application.service.keyprov;

/**
 * PAR-PROTO Wire Mapper 输入上下文（迁入 VMD 既有实现）。
 *
 * @param requestId       TBOX 稳定 requestId（UTF-8）
 * @param businessDomain   业务域（首期 V2C_COMM，UTF-8）
 * @author hwyz_leo
 */
public record KeyProvisioningWireContext(String requestId, String businessDomain) {

    public KeyProvisioningWireContext {
        if (requestId == null || requestId.isBlank()) {
            throw new IllegalArgumentException("KeyProvisioningWireContext.requestId 不能为空");
        }
        if (businessDomain == null || businessDomain.isBlank()) {
            throw new IllegalArgumentException("KeyProvisioningWireContext.businessDomain 不能为空");
        }
    }
}
