package net.hwyz.iov.cloud.sec.viam.service.domain.model.port;

import java.time.Instant;

/**
 * 设备证明证据（SEC-VIAM-DSN-CR-003 / D-VIAM-3-02）
 * <p>
 * 由证明体解析并核验后得到的“VIAM 已登记事实”：设备身份 hsmUid 与证书事实。
 * 不含业务结论、不含 VIN、不含证书/签名原文。
 * </p>
 *
 * @param hsmUid       证书 Subject CN 归一化后的设备身份（= 已登记 hsm_uid）
 * @param certSn       证书序列号（provider canonical form：小写 hex，无冒号）
 * @param fingerprint  叶子证书 SHA-256 指纹（小写 hex）
 * @param deviceSn     证书登记事实中的设备序列号（可空）
 * @param notAfter     证书有效期截止（可空，缺失时不据此判过期）
 * @param verifiedAt   证明校验完成时间
 * @author hwyz_leo
 */
public record DeviceProofEvidence(String hsmUid, String certSn, String fingerprint, String deviceSn,
                                  Instant notAfter, Instant verifiedAt) {
}
