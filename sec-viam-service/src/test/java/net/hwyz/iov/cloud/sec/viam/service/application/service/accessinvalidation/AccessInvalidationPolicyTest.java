package net.hwyz.iov.cloud.sec.viam.service.application.service.accessinvalidation;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 访问失效乱序判定纯函数测试（SEC-VIAM-DSN-CR-001 / FR-VIAM-008 / G-3）
 * <p>
 * 必测场景：block(v10) → unblock(v11) → 旧 block(v10) 事件迟到 → 不得再次封禁
 * 已经恢复且重新认证的会话；旧撤销事件不得漏断/误断新会话。
 * </p>
 *
 * @author hwyz_leo
 */
class AccessInvalidationPolicyTest {

    @Test
    void sessionAuthorizedAfterEventIsNotSubject() {
        // 会话在 v11（unblock 后重新认证）授权，迟到 block(v10) 事件 → 不执行
        assertFalse(AccessInvalidationPolicy.shouldEnforce(10L, 11L));
    }

    @Test
    void sessionAuthorizedBeforeEventIsSubject() {
        // 会话在 v9 授权，block(v10) → 必须执行（不因重连换 generation 逃逸）
        assertTrue(AccessInvalidationPolicy.shouldEnforce(10L, 9L));
    }

    @Test
    void equalVersionIsStale() {
        // 事件版本与授权版本相同 → 该会话已覆盖事件语义，不重复执行
        assertFalse(AccessInvalidationPolicy.shouldEnforce(10L, 10L));
    }

    @Test
    void lateBlockAfterUnblockIsStaleByCurrentState() {
        // block(v10) 事件在 unblock(v11) 后迟到：当前状态非 BLOCKED/RETIRED 且事件版本落后 → stale
        assertTrue(AccessInvalidationPolicy.isStaleByCurrentState(11L, 10L, "ACTIVE", true));
        assertTrue(AccessInvalidationPolicy.isStaleByCurrentState(11L, 10L, "ACTIVATING", true));
        // 当前仍 BLOCKED → 非 stale（主体仍被封禁，旧事件与当前一致，不得放行）
        assertFalse(AccessInvalidationPolicy.isStaleByCurrentState(12L, 10L, "BLOCKED", true));
    }

    @Test
    void nonBlockingEventsNotVersionStale() {
        // 单连接处置（CONNECTION_DISPOSAL）不按版本 stale
        assertFalse(AccessInvalidationPolicy.isStaleByCurrentState(11L, 10L, "ACTIVE", false));
    }
}
