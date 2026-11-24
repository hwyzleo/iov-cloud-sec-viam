package net.hwyz.iov.cloud.sec.viam.service.adapter.kafka.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

import java.time.Instant;

/**
 * VMD 车辆-零件绑定变更事件载荷（SEC-VIAM-DSN-CR-006 / D-VIAM-028）
 * <p>
 * 仅消费触发信号与寻址键（vin/eventId/bindingId）；身份与绑定事实一律回查 VMD 只读快照，
 * 不从本载荷推断 `hsmUid`、不采信自报类别作为登记依据。
 * </p>
 *
 * @author hwyz_leo
 * @since 2026-11-24
 */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class VmdPartBindingChangedPayload {

    /** 事件唯一ID（VMD 生成，幂等键） */
    private String eventId;

    /** 是否重放事件 */
    private Boolean replay;

    /** 重放ID */
    private String replayId;

    /** 导入批次号 */
    private String batchNum;

    /** 车架号（快照回查寻址键） */
    private String vin;

    /** 绑定ID（= vehicle_part.id） */
    private Long bindingId;

    /** 零件编码 */
    private String partCode;

    /** 零件序列号 */
    private String sn;

    /** 设备类别（VMD 取自 MDM 节点；仅作日志与指标，不作身份依据） */
    private String deviceCategory;

    /** 车载节点代码 */
    private String vehicleNodeCode;

    /** 变更类型：BIND / UNBIND / REPLACE */
    private String changeType;

    /** 被替换的绑定ID */
    private Long replaceOfBindingId;

    /** 事件发生时间 */
    private Instant occurredAt;

    /** 事件序 */
    private Long seq;
}
