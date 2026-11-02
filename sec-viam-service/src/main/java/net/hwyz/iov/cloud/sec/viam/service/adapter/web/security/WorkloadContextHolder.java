package net.hwyz.iov.cloud.sec.viam.service.adapter.web.security;

/**
 * 请求级 workload 上下文持有器（SEC-VIAM-DSN-CR-001 / G-4）。
 * <p>
 * 线程绑定；由 {@link ServiceIdentityInterceptor} 在验签成功后写入，请求结束后清理。
 * </p>
 *
 * @author hwyz_leo
 */
public final class WorkloadContextHolder {

    private static final ThreadLocal<WorkloadContext> CONTEXT = new ThreadLocal<>();

    private WorkloadContextHolder() {
    }

    public static void set(WorkloadContext context) {
        CONTEXT.set(context);
    }

    public static WorkloadContext get() {
        return CONTEXT.get();
    }

    public static void clear() {
        CONTEXT.remove();
    }
}
