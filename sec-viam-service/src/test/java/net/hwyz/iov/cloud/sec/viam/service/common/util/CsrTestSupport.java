package net.hwyz.iov.cloud.sec.viam.service.common.util;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

/**
 * CSR 测试夹具（SEC-VIAM-DSN-CR-004）：生成真实自签名 PKCS#10 CSR。
 * <p>
 * 仅用于测试：不涉及私钥持久化，密钥对在内存中一次性生成。
 * </p>
 *
 * @author hwyz_leo
 */
public final class CsrTestSupport {

    private CsrTestSupport() {
    }

    /**
     * 生成 EC P-256 密钥对。
     */
    public static KeyPair keyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(256);
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("EC P-256 密钥对生成失败", e);
        }
    }

    /**
     * 生成 Subject=CN 的合法 CSR（DER Base64）。
     */
    public static String csr(String commonName) {
        return csr(new X500Name("CN=" + commonName), keyPair());
    }

    /**
     * 生成 Subject=CN 且附加 RDN（如 {@code OU=VIN1}）的合法 CSR（DER Base64）。
     */
    public static String csr(String commonName, String extraRdn) {
        return csr(new X500Name("CN=" + commonName + "," + extraRdn), keyPair());
    }

    /**
     * 以给定 Subject 与密钥对生成合法 CSR（DER Base64）。
     */
    public static String csr(X500Name subject, KeyPair keyPair) {
        try {
            PKCS10CertificationRequest request = new JcaPKCS10CertificationRequestBuilder(
                    subject, keyPair.getPublic())
                    .build(new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate()));
            return Base64.getEncoder().encodeToString(request.getEncoded());
        } catch (Exception e) {
            throw new IllegalStateException("CSR 生成失败", e);
        }
    }
}
