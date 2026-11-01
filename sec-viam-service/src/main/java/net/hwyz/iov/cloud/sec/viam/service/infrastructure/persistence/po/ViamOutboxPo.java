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
 * VIAM 通用 Outbox PO（SEC-VIAM-DSN-CR-001 / D-VIAM-008）
 *
 * @author hwyz_leo
 */
@Getter
@Setter
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@TableName("tb_viam_outbox")
public class ViamOutboxPo extends BasePo {

    private static final long serialVersionUID = 1L;

    @TableId(value = "id", type = IdType.AUTO)
    private Long id;

    @TableField("event_id")
    private String eventId;

    @TableField("event_type")
    private String eventType;

    @TableField("aggregate_type")
    private String aggregateType;

    @TableField("aggregate_id")
    private String aggregateId;

    @TableField("aggregate_version")
    private Long aggregateVersion;

    @TableField("topic")
    private String topic;

    @TableField("message_key")
    private String messageKey;

    @TableField("payload")
    private String payload;

    @TableField("publish_state")
    private String publishState;

    @TableField("retry_count")
    private int retryCount;

    @TableField("next_retry_time")
    private LocalDateTime nextRetryTime;

    @TableField("published_at")
    private LocalDateTime publishedAt;

    @TableField("last_error")
    private String lastError;

    @TableField("source_type")
    private String sourceType;

    @TableField("source_ref_id")
    private String sourceRefId;
}
