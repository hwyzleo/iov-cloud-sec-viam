package net.hwyz.iov.cloud.sec.viam.service.common.util;

import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * CSR 编码归一化测试（SEC-VIAM-DSN-CR-006 修复 / 702204）
 * <p>
 * 线上缺陷：MPT 粘贴 PEM 形式的 CSR 时，校验器兼容剥离而适配器严格解码，
 * 在调用 PKI 前抛 IllegalArgumentException（500）。归一化必须覆盖：
 * 标准 Base64、Base64URL、PEM 包裹、含空白；非法输入统一 702204。
 * </p>
 *
 * @author hwyz_leo
 */
@DisplayName("CSR 编码归一化")
class CertificateCsrValidatorEncodingTest {

    private static final String STANDARD = CsrTestSupport.csr("UID-1");
    private static final byte[] DER = Base64.getDecoder().decode(STANDARD);

    @Test
    @DisplayName("标准 Base64：原样归一化")
    void shouldKeepStandardBase64() {
        assertEquals(STANDARD, CertificateCsrValidator.toStandardBase64(STANDARD));
    }

    @Test
    @DisplayName("含换行/空白的 Base64：去除空白")
    void shouldStripWhitespace() {
        String wrapped = STANDARD.substring(0, 20) + "\n" + STANDARD.substring(20) + "\r\n";
        assertEquals(STANDARD, CertificateCsrValidator.toStandardBase64(wrapped));
    }

    @Test
    @DisplayName("PEM 包裹（-----BEGIN CERTIFICATE REQUEST-----）：剥离头尾后可解码")
    void shouldAcceptPemWrappedCsr() {
        String pem = "-----BEGIN CERTIFICATE REQUEST-----\n"
                + STANDARD.replaceAll("(.{64})", "$1\n") + "\n-----END CERTIFICATE REQUEST-----\n";

        String normalized = CertificateCsrValidator.toStandardBase64(pem);

        assertEquals(STANDARD, normalized);
        assertArrayEquals(DER, Base64.getDecoder().decode(normalized));
    }

    @Test
    @DisplayName("Base64URL 字符集（- _）：映射为标准 Base64")
    void shouldAcceptBase64Url() {
        String url = Base64.getUrlEncoder().encodeToString(DER);
        assertEquals(STANDARD, CertificateCsrValidator.toStandardBase64(url));
    }

    @Test
    @DisplayName("非法编码：统一 702204，不抛 IllegalArgumentException")
    void shouldRejectInvalidEncodingWith702204() {
        ViamServiceException ex = assertThrows(ViamServiceException.class,
                () -> CertificateCsrValidator.toStandardBase64("not-base64-@@@"));

        assertEquals(ViamErrorCode.CERTIFICATE_CSR_INVALID.getCode(), ex.getCode());
    }

    @Test
    @DisplayName("空值：702204")
    void shouldRejectBlank() {
        assertEquals(ViamErrorCode.CERTIFICATE_CSR_INVALID.getCode(),
                assertThrows(ViamServiceException.class,
                        () -> CertificateCsrValidator.toStandardBase64("   ")).getCode());
    }
}
