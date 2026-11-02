package net.hwyz.iov.cloud.sec.viam.api.security;

/**
 * VIAM 官方服务间认证请求头契约（SEC-VIAM-DSN-CR-001 / FR-VIAM-004 / G-4）。
 * <p>
 * VAGW / OAPI / MES 等调用方访问 {@code /api/service/**} 时必须携带本组请求头；
 * 身份由 {@link ViamServiceSignature} 验签建立，请求头仅承载签名材料，不是认证凭据。
 * 所有 Secret 经环境变量注入，禁止出现在 Nacos / 日志 / 请求体。
 * </p>
 *
 * @author hwyz_leo
 */
public final class ViamServiceAuthHeaders {

    private ViamServiceAuthHeaders() {
    }

    /** 调用方服务身份（如 VAGW / OAPI_MES / MPT_BATCH）；仅身份映射字段 */
    public static final String CLIENT_ID = "X-Viam-Client-Id";

    /** 调用方 Secret 的 keyId（用于轮换；密钥正文不随请求传输） */
    public static final String KEY_ID = "X-Viam-Key-Id";

    /** 目标服务 audience（固定 sec-viam，防签名被转用到其它服务） */
    public static final String AUDIENCE = "X-Viam-Audience";

    /** 请求方法（规范化小写） */
    public static final String METHOD = "X-Viam-Method";

    /** 规范化 path + query */
    public static final String PATH = "X-Viam-Path";

    /** 原始 body 的 SHA-256 hex */
    public static final String BODY_DIGEST = "X-Viam-Body-Digest";

    /** 客户端 epoch 毫秒时间戳（有效窗口内校验） */
    public static final String TIMESTAMP = "X-Viam-Timestamp";

    /** 单次随机 nonce（重放检查；同 clientId+nonce 不得重复） */
    public static final String NONCE = "X-Viam-Nonce";

    /** HMAC-SHA256 签名（hex，覆盖上述规范串） */
    public static final String SIGNATURE = "X-Viam-Signature";

    /** 签名算法版本（v1） */
    public static final String ALGORITHM = "X-Viam-Algorithm";
}
