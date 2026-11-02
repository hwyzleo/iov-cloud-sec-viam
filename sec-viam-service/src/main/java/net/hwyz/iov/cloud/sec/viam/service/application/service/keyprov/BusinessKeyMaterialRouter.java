package net.hwyz.iov.cloud.sec.viam.service.application.service.keyprov;

import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.framework.security.crypto.BusinessKeyMaterialTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.KeyProvisioningTemplate;
import net.hwyz.iov.cloud.framework.security.crypto.model.BizType;
import net.hwyz.iov.cloud.framework.security.crypto.model.KeyMaterialModel;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;

/**
 * 业务密钥材料模型路由（迁入 VMD 既有实现）。
 * <p>
 * 按 {@code BizType.materialModel()} <strong>显式</strong>路由，禁止依据方法调用动态猜测，禁止隐式回退：
 * <ul>
 *   <li>{@link KeyMaterialModel#DERIVED_ROOT} → {@link KeyProvisioningTemplate#deriveAndWrap}</li>
 *   <li>{@link KeyMaterialModel#RANDOM_MATERIAL} → {@link BusinessKeyMaterialTemplate#create}/{@code wrap}/{@code revoke}</li>
 *   <li>{@code null}（不适用）→ 两条路径均拒绝</li>
 * </ul>
 * V2C（{@code V2C_COMM_ROOT}）固定走根派生（DERIVED_ROOT）；目录状态仍由 VIAM 管理，
 * Provider 只返回密码学操作/材料状态。
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
public class BusinessKeyMaterialRouter {

    private final ObjectProvider<KeyProvisioningTemplate> derivedRootProvider;
    private final ObjectProvider<BusinessKeyMaterialTemplate> randomMaterialProvider;

    public BusinessKeyMaterialRouter(ObjectProvider<KeyProvisioningTemplate> derivedRootProvider,
                                     ObjectProvider<BusinessKeyMaterialTemplate> randomMaterialProvider) {
        this.derivedRootProvider = derivedRootProvider;
        this.randomMaterialProvider = randomMaterialProvider;
    }

    /**
     * 是否为根派生型（DERIVED_ROOT）。
     */
    public boolean isDerivedRoot(BizType bizType) {
        return bizType != null && bizType.supportsDerivedRoot();
    }

    /**
     * 取根派生门面；非 DERIVED_ROOT 一律拒绝（fail-closed，禁隐式回退）。
     */
    public KeyProvisioningTemplate requireDerivedRoot(BizType bizType) {
        if (bizType == null || !bizType.supportsDerivedRoot()
                || bizType.materialModel() != KeyMaterialModel.DERIVED_ROOT) {
            throw new ViamServiceException(ViamErrorCode.BUSINESS_KEY_DERIVATION_REJECTED,
                    "bizType 不是根派生型（materialModel="
                            + (bizType == null ? null : bizType.materialModel()) + "）: " + bizType);
        }
        KeyProvisioningTemplate template = derivedRootProvider.getIfAvailable();
        if (template == null) {
            throw new ViamServiceException(ViamErrorCode.BUSINESS_KEY_KMS_UNAVAILABLE,
                    "framework 根派生门面未装配（viam.crypto.provisioning.enabled=false）");
        }
        return template;
    }

    /**
     * 取随机材料门面；非 RANDOM_MATERIAL 一律拒绝（fail-closed，禁隐式回退）。
     */
    public BusinessKeyMaterialTemplate requireRandomMaterial(BizType bizType) {
        if (bizType == null || !bizType.supportsRandomMaterial()
                || bizType.materialModel() != KeyMaterialModel.RANDOM_MATERIAL) {
            throw new ViamServiceException(ViamErrorCode.BUSINESS_KEY_DERIVATION_REJECTED,
                    "bizType 不是独立随机材料型（materialModel="
                            + (bizType == null ? null : bizType.materialModel()) + "）: " + bizType);
        }
        BusinessKeyMaterialTemplate template = randomMaterialProvider.getIfAvailable();
        if (template == null) {
            throw new ViamServiceException(ViamErrorCode.BUSINESS_KEY_KMS_UNAVAILABLE,
                    "framework 随机材料门面未装配（viam.crypto.business-key.enabled=false）");
        }
        return template;
    }

    /**
     * 是否装配了根派生门面（供 Health / 诊断使用，不触发拒绝）。
     */
    public boolean derivedRootAvailable() {
        return derivedRootProvider.getIfAvailable() != null;
    }
}
