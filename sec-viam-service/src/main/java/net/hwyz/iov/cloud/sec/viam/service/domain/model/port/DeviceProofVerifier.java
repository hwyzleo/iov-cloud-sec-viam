package net.hwyz.iov.cloud.sec.viam.service.domain.model.port;

import net.hwyz.iov.cloud.sec.viam.api.vo.enums.DeviceProofType;

import java.time.Instant;

/**
 * 设备证明校验端口（SEC-VIAM-DSN-CR-003 §13.8 / D-VIAM-3-04）
 * <p>
 * 只负责“证明体是否真实成立”并返回已登记证据；主体状态、安全结论与业务语义
 * 由应用层编排。实现必须复用既有 framework-security PKI 能力，不新建第二套 PKI 客户端。
 * </p>
 *
 * @author hwyz_leo
 */
public interface DeviceProofVerifier {

    /**
     * 校验设备证明。
     *
     * @param proofType  证明类型
     * @param proofBytes 已解码的证明体（MTLS_CERT：证书 DER；KEY_SIGNATURE：签名字节）
     * @param nonce      nonce 原文（KEY_SIGNATURE 的签名对象为 UTF-8 字节）
     * @param deviceId   设备标识线索（可空，仅用于定位已登记证书）
     * @param verifiedAt 校验时刻
     * @return 已登记证据
     * @throws net.hwyz.iov.cloud.sec.viam.service.common.exception.DeviceProofInvalidException 证明无效
     * @throws net.hwyz.iov.cloud.sec.viam.service.common.exception.DeviceProofDependencyException 依赖不可用/不确定
     */
    DeviceProofEvidence verify(DeviceProofType proofType, byte[] proofBytes, String nonce, String deviceId,
                               Instant verifiedAt);
}
