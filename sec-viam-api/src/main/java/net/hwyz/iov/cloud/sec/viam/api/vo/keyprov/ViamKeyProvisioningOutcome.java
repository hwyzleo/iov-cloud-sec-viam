package net.hwyz.iov.cloud.sec.viam.api.vo.keyprov;

/**
 * Keyprov Service 调用结果类别（SEC-VIAM-DSN-CR-001 / FR-VIAM-003）。
 * <p>
 * 区分"请求未执行（UNAVAILABLE）""明确拒绝（REJECTED）""结果未知（OUTCOME_UNKNOWN）"
 * 与"成功（SUCCESS）"，供 VAGW 决定是否重试、是否以原 requestId 对账。
 * </p>
 *
 * @author hwyz_leo
 */
public enum ViamKeyProvisioningOutcome {

    /** 成功返回 canonical 下行 payload */
    SUCCESS,

    /** 明确业务拒绝（协议、身份、绑定、幂等、状态等） */
    REJECTED,

    /** 结果未知：请求可能已执行，须以原 requestId 调 /status 对账，不得自动重放 */
    OUTCOME_UNKNOWN,

    /** 依赖不可用/未执行：调用方可按策略有限重试 */
    UNAVAILABLE
}
