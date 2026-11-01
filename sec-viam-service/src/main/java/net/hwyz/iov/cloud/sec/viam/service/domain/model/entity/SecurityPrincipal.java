package net.hwyz.iov.cloud.sec.viam.service.domain.model.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

/**
 * 设备安全主体实体（SEC-VIAM-DSN-CR-001 / FR-VIAM-001）
 * <p>
 * 稳定 principalId 与设备资产键/VIN 分开；hsmUid 是安全身份属性，TBOX SN 仅资产追溯。
 * 身份关联由受信入站登记、VMD 事实和迁入凭据记录建立，不得仅信客户端自报 UID。
 * </p>
 *
 * @author hwyz_leo
 */
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityPrincipal {

    /** 稳定安全主体ID */
    private String principalId;

    /** 权威 HSM UID（证书CN / MQTT device identity / Envelope device_id 规范值） */
    private String hsmUid;

    /** 主体登记来源（受信入站登记/VMD事实/迁移） */
    private String sourceSystem;

    /** 来源引用（如VMD binding id / 迁移记录号） */
    private String sourceRefId;

    /** 主体状态：ACTIVE/BLOCKED/RETIRED */
    private PrincipalState state;

    /** 安全封禁原因（可解释 reason） */
    private String blockReason;

    /** 封禁生效时限 */
    private Instant blockEffectiveAt;

    /** 创建时间（UTC Instant） */
    private Instant createdAt;

    /** 主体状态 */
    public enum PrincipalState {
        ACTIVE, BLOCKED, RETIRED
    }

    /**
     * 安全封禁：状态迁移至 BLOCKED，携带可解释 reason 与生效时限。
     */
    public void block(String reason, Instant effectiveAt) {
        if (state == PrincipalState.RETIRED) {
            throw new IllegalStateException("已退役主体不可封禁");
        }
        this.state = PrincipalState.BLOCKED;
        this.blockReason = reason;
        this.blockEffectiveAt = effectiveAt;
    }

    /**
     * 恢复：仅 BLOCKED 可恢复 ACTIVE。
     */
    public void unblock() {
        if (state != PrincipalState.BLOCKED) {
            throw new IllegalStateException("仅封禁主体可恢复");
        }
        this.state = PrincipalState.ACTIVE;
        this.blockReason = null;
        this.blockEffectiveAt = null;
    }
}
