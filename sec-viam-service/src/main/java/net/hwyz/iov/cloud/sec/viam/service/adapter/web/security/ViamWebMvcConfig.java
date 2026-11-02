package net.hwyz.iov.cloud.sec.viam.service.adapter.web.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * VIAM Web 安全配置（G-4）。
 * <p>
 * 注册服务身份认证拦截器；拦截器内部仅对 {@code /api/service/**} 生效，
 * 其它路径（MPT 管理、健康检查）走既有框架认证链。
 * </p>
 *
 * @author hwyz_leo
 */
@Configuration
@RequiredArgsConstructor
public class ViamWebMvcConfig implements WebMvcConfigurer {

    private final ServiceIdentityInterceptor serviceIdentityInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(serviceIdentityInterceptor).addPathPatterns("/**");
    }
}
