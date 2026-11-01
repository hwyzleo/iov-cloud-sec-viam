package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;
import net.hwyz.iov.cloud.framework.mysql.po.BasePo;

import java.time.LocalDateTime;

/**
 * VIAM 入站事件收件箱 PO（SEC-VIAM-DSN-CR-001 / D-VIAM-008）
 *
 * @author hwyz_leo
 */
@Getter
@Setter
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@TableName("tb_viam_inbox")
public class ViamInboxPo extends BasePo {

    private static final long serialVersionUID = 1L;

    @TableId(value = "id", type = IdType.AUTO)
    private Long id;

    @TableField("event_id")
    private String eventId;

    @TableField("event_type")
    private String eventType;

    @TableField("source_topic")
    private String sourceTopic;

    @TableField("source_ref_id")
    private String sourceRefId;

    @TableField("payload_digest")
    private String payloadDigest;

    @TableField("received_at")
    private LocalDateTime receivedAt;

    @TableField("processed_state")
    private String processedState;

    @TableField("quarantine_reason")
    private String quarantineReason;

    @TableField("retry_count")
    private int retryCount;

    @TableField("next_retry_time")
    private LocalDateTime nextRetryTime;

    @TableField("process_error")
    private String processError;
}
