package net.hwyz.iov.cloud.sec.viam.service.adapter.web.security;

/**
 * nonce 重放防护（G-4）：同一 clientId+nonce 只能声明一次。
 * <p>
 * 实现必须原子占用；占用后保留至签名时间戳窗口结束，防止重放。
 * </p>
 *
 * @author hwyz_leo
 */
public interface NonceReplayGuard {

    /**
     * 尝试原子占用 nonce。
     *
     * @param clientId    调用方身份
     * @param nonce       nonce 值
     * @param ttlSeconds  保留时长（≥ 时间戳窗口）
     * @return true=首次占用可继续；false=已占用（重放）
     */
    boolean tryClaim(String clientId, String nonce, long ttlSeconds);
}
