package net.hwyz.iov.cloud.sec.viam.api.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * 车辆接入身份解析结果VO（SEC-VIAM-DSN-CR-001 / FR-VIAM-004）
 * <p>
 * resolve 是安全身份解析，不是准入许可；不替代吊销和业务授权。
 * </p>
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class VehicleAccessIdentityResultVo {

    /** 车辆VIN */
    private String vin;

    /** 解析状态: RESOLVED / UNRESOLVED */
    private String status;

    /** 解析原因 */
    private String reason;

    /** HSM UID（证书CN / MQTT device identity / Envelope device_id 的规范值） */
    private String hsmUid;

    /** 安全主体ID（VIAM 稳定 principalId） */
    private String principalId;

    /** TBOX 序列号（仅资产追溯，不得作为 MQTT device key） */
    private String tboxSn;

    /** 绑定版本 */
    private Long bindingVersion;

    /** 绑定最近更新时间 */
    private Instant bindingUpdatedAt;
}
