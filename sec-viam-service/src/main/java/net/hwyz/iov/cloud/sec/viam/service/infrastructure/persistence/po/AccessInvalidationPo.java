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

@Getter
@Setter
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@TableName("tb_viam_access_invalidation")
public class AccessInvalidationPo extends BasePo {

    private static final long serialVersionUID = 1L;

    @TableId(value = "id", type = IdType.AUTO)
    private Long id;

        @TableField("invalidation_id")
    private String invalidationId;

    @TableField("principal_id")
    private String principalId;

    @TableField("hsm_uid")
    private String hsmUid;

    @TableField("vin")
    private String vin;

    @TableField("device_sn")
    private String deviceSn;

    @TableField("invalidation_type")
    private String invalidationType;

    @TableField("reason")
    private String reason;

    @TableField("scope")
    private String scope;

    @TableField("security_version")
    private Long securityVersion;

    @TableField("binding_version")
    private Long bindingVersion;

    @TableField("target_generation")
    private Long targetGeneration;

    @TableField("effective_at")
    private LocalDateTime effectiveAt;

    @TableField("effective_by")
    private LocalDateTime effectiveBy;

    @TableField("status")
    private String status;

    @TableField("receipt_state")
    private String receiptState;

    @TableField("receipt_detail")
    private String receiptDetail;

    @TableField("execution_result_json")
    private String executionResultJson;

    @TableField("event_payload_digest")
    private String eventPayloadDigest;

    @TableField("retry_count")
    private Integer retryCount;

    @TableField("last_retry_at")
    private LocalDateTime lastRetryAt;

    @TableField("timeout_alerted")
    private Boolean timeoutAlerted;

}
