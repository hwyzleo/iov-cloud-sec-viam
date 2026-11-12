package net.hwyz.iov.cloud.sec.viam.service.adapter.web.controller.mpt;

import lombok.RequiredArgsConstructor;
import net.hwyz.iov.cloud.framework.security.util.SecurityUtils;
import net.hwyz.iov.cloud.framework.web.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

/**
 * MPT 操作人上下文（SEC-VIAM-DSN-CR-002 / D-VIAM-014）
 * <p>
 * 操作人一律从 EIAM 认证会话解析，禁止请求体/参数自报；
 * 与 §D-VIAM-009「无人工改安全事实」一致：只标识操作人，不参与安全事实判定。
 * 本组件同时兼容单元测试（无 SecurityContext 时返回 null 而非抛错）。
 * </p>
 *
 * @author hwyz_leo
 */
@Component
public class SecurityOperatorContext {

    /**
     * 当前登录用户ID；未认证返回 null（由下游 fail-closed 或审计留空）。
     */
    public String operatorId() {
        try {
            Long userId = SecurityUtils.getUserId();
            return userId != null ? String.valueOf(userId) : null;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 当前登录用户名称；未认证返回 null。
     */
    public String operatorName() {
        try {
            return SecurityContextHolder.getUserName();
        } catch (Exception e) {
            return null;
        }
    }
}
