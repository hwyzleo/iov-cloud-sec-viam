package net.hwyz.iov.cloud.sec.viam.api.vo.enums;

import java.util.Arrays;

/**
 * 设备接入裁决结果枚举（SEC-VIAM-DSN-CR-001 / FR-VIAM-004）
 *
 * @author hwyz_leo
 */
public enum AdmissionDecision {

    /** 允许接入（本次认证/准入通过，不等于成功建链） */
    ALLOW,
    /** 拒绝接入（fail-closed） */
    DENY;

    public static AdmissionDecision valOf(String val) {
        return Arrays.stream(values())
                .filter(decision -> decision.name().equals(val))
                .findFirst()
                .orElse(null);
    }
}
