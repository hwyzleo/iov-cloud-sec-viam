package net.hwyz.iov.cloud.sec.viam.service.application.service.accessinvalidation;

/**
 * 访问失效执行判定纯函数（SEC-VIAM-DSN-CR-001 / FR-VIAM-008 / G-3）。
 * <p>
 * 乱序旧事件不得误断新会话：VAGW 依据「会话被授权时的安全版本」与「事件携带的安全版本」
 * 判定是否执行。主体/凭据/绑定级撤销（PRINCIPAL_REVOCATION）不因重连换 generation 逃逸，
 * 但被新版本安全状态覆盖的旧事件（例如 block(v10) 之后 unblock(v11) 并重新认证）不得再次生效。
 * </p>
 *
 * @author hwyz_leo
 */
public final class AccessInvalidationPolicy {

    private AccessInvalidationPolicy() {
    }

    /**
     * 判定旧失效事件是否仍应执行（供 VAGW 消费端与 VIAM 回执校验共用语义）。
     *
     * @param eventSecurityVersion       事件携带的安全状态版本
     * @param sessionAuthorizedVersion   目标会话被授权时的安全状态版本
     * @return true=应执行（会话授权版本落后于事件版本，仍在撤销范围内）
     */
    public static boolean shouldEnforce(long eventSecurityVersion, long sessionAuthorizedVersion) {
        // 会话在事件版本之后才被授权 → 该会话不受此事件影响（乱序旧事件不误断新会话）
        return eventSecurityVersion > sessionAuthorizedVersion;
    }

    /**
     * 判定事件是否因当前安全状态已覆盖而成为 stale（VIAM 回执/对账侧）。
     *
     * @param currentSecurityVersion 当前安全状态版本（单调递增）
     * @param eventSecurityVersion   事件版本
     * @param currentState           BLOCKED/RETIRED/ACTIVE 等当前状态
     * @param targetStateBlocked     事件目标是否封禁类（BLOCK/RETIRE/REVOKE）
     * @return true=旧事件已被覆盖（例如 block(v10) 事件在 unblock(v11) 后迟到），不得再次生效
     */
    public static boolean isStaleByCurrentState(long currentSecurityVersion, long eventSecurityVersion,
                                                String currentState, boolean targetStateBlocked) {
        if (eventSecurityVersion >= currentSecurityVersion) {
            return false; // 事件版本不落后于当前，仍有效
        }
        if (!targetStateBlocked) {
            return false; // 非封禁类事件（如单连接处置）不按版本 stale
        }
        // 事件版本落后且当前状态不是封禁类 → 旧封禁已被解除/覆盖（block→unblock 场景）
        return !"BLOCKED".equals(currentState) && !"RETIRED".equals(currentState);
    }
}
