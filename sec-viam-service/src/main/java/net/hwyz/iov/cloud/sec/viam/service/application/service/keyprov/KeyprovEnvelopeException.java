package net.hwyz.iov.cloud.sec.viam.service.application.service.keyprov;

/**
 * Keyprov canonical 信封完整性异常（迁入 VMD 既有语义）。
 * <p>
 * 信封/冻结证据/租约字节级不一致时抛出（fail-closed，不可重试），
 * 由应用门面映射为稳定 702xxx 错误。
 * </p>
 *
 * @author hwyz_leo
 */
public class KeyprovEnvelopeException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public KeyprovEnvelopeException(String message) {
        super(message);
    }

    public KeyprovEnvelopeException(String message, Throwable cause) {
        super(message, cause);
    }
}
