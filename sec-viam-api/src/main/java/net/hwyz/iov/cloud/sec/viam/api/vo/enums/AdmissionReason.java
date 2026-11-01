package net.hwyz.iov.cloud.sec.viam.api.vo.enums;

import java.util.Arrays;

/**
 * 设备接入裁决原因枚举（SEC-VIAM-DSN-CR-001 / FR-VIAM-004）
 * <p>
 * 语义枚举，VAGW 据此映射 EMQX 错误码；身份不一致、证书吊销与依赖故障必须分别归类。
 * </p>
 *
 * @author hwyz_leo
 */
public enum AdmissionReason {

    /** 无（仅 ALLOW 使用） */
    NONE,
    /** uid 在受信事实（安全主体登记/VMD投影）中不存在 */
    UID_UNKNOWN,
    /** framework 返回的证书 subjectCommonName 与请求 uid 规范化后不一致 */
    IDENTITY_MISMATCH,
    /** 设备无当前有效（ACTIVE）车辆绑定 */
    UNBOUND,
    /** 同一设备存在多条 ACTIVE 绑定，fail-closed */
    BINDING_CONFLICT,
    /** 证书已被吊销 */
    CERT_REVOKED,
    /** 证书已过期 */
    CERT_EXPIRED,
    /** 设备被安全封禁 */
    DEVICE_BLOCKED,
    /** 设备已退役 */
    DEVICE_RETIRED,
    /** PKI 吊销依赖不可用或结果不确定，fail-closed */
    DEPENDENCY_UNAVAILABLE;

    public static AdmissionReason valOf(String val) {
        return Arrays.stream(values())
                .filter(reason -> reason.name().equals(val))
                .findFirst()
                .orElse(null);
    }
}
