package net.hwyz.iov.cloud.sec.viam.service.domain.model.query;

import java.time.Instant;

/**
 * 证书申请管理面查询条件（SEC-VIAM-DSN-CR-002 / FR-VIAM-002 / D-VIAM-012）
 * <p>
 * 空条件表示不限制；时间窗按创建时间闭区间过滤。
 * </p>
 *
 * @author hwyz_leo
 */
public record CertificateQuery(
        String vin,
        String deviceSn,
        String certSn,
        String requestId,
        String status,
        String sourceSystem,
        Instant beginTime,
        Instant endTime) {

    /**
     * 去除首尾空白并把空串归一为 null，避免空条件参与 SQL 等值匹配。
     */
    public CertificateQuery {
        vin = blankToNull(vin);
        deviceSn = blankToNull(deviceSn);
        certSn = blankToNull(certSn);
        requestId = blankToNull(requestId);
        status = blankToNull(status);
        sourceSystem = blankToNull(sourceSystem);
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
