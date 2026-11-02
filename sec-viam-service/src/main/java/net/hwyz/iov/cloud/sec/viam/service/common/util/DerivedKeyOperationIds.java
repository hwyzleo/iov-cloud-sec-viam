package net.hwyz.iov.cloud.sec.viam.service.common.util;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

/**
 * 根派生操作标识生成（迁入 VMD 既有实现，语义保持）。
 * <p>
 * {@code operationId} 是对账主键：同一 (requestId, purpose, businessKeyVersion) 必须恒定；
 * {@code idempotencyKey} 同一上下文恒定，供 Provider 幂等重放。均以确定性
 * {@link UUID#nameUUIDFromBytes(byte[])} 派生，不引入随机或时间因子。
 * </p>
 *
 * @author hwyz_leo
 */
public final class DerivedKeyOperationIds {

    private DerivedKeyOperationIds() {
    }

    /**
     * 稳定 operationId：同 (requestId, purpose, businessKeyVersion) 恒定。
     */
    public static String operationId(String requestId, String purpose, Long businessKeyVersion) {
        return UUID.nameUUIDFromBytes(("keyprov-op|" + nullSafe(requestId) + "|" + nullSafe(purpose) + "|"
                + (businessKeyVersion == null ? 0 : businessKeyVersion)).getBytes(StandardCharsets.UTF_8)).toString();
    }

    /**
     * 稳定幂等键：同 (requestId, deviceSn, purpose, businessKeyVersion, derivationVersion) 恒定。
     */
    public static String idempotencyKey(String requestId, String deviceSn, String purpose,
                                        Long businessKeyVersion, String derivationVersion) {
        return UUID.nameUUIDFromBytes(("keyprov-ik|" + nullSafe(requestId) + "|" + nullSafe(deviceSn) + "|"
                + nullSafe(purpose) + "|" + (businessKeyVersion == null ? 0 : businessKeyVersion) + "|"
                + nullSafe(derivationVersion)).getBytes(StandardCharsets.UTF_8)).toString();
    }

    private static String nullSafe(String value) {
        return value == null ? "" : value;
    }
}
