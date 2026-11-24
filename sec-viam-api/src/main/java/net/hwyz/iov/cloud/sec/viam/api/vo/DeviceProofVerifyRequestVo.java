package net.hwyz.iov.cloud.sec.viam.api.vo;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 设备证明校验请求VO（SEC-VIAM-DSN-CR-003 / FR-VIAM-3-1）
 * <p>
 * 请求只带线索、不带结论：{@code devicePrincipal/deviceSn} 由 VIAM 已登记事实返回，
 * 不接受调用方声明的设备主体或 VIN（D-VIAM-3-02）。
 * </p>
 * <ul>
 *   <li>{@code proofType=MTLS_CERT}：{@code proof} 为本次连接实际叶子证书（Base64 DER，或 PEM 单证书/链，
 *       仅取第一张叶子证书）；设备身份取证书 Subject CN，{@code deviceId} 可选，仅用于一致性交叉校验。</li>
 *   <li>{@code proofType=KEY_SIGNATURE}：{@code proof} 为对 {@code nonce} <b>Base64 解码后原始字节</b>的签名（Base64）；
 *       {@code deviceId} 必填，通常为 deviceSn（证书设备的唯一值 hsmUid 亦可）。</li>
 * </ul>
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DeviceProofVerifyRequestVo {

    /** 证明类型：MTLS_CERT / KEY_SIGNATURE */
    @NotBlank(message = "证明类型不能为空")
    @Size(max = 32, message = "证明类型长度非法")
    private String proofType;

    /**
     * 证明体（标准 Base64）：MTLS_CERT 为叶子证书 DER（≤16 KiB，Base64 后≤22 KiB）；
     * KEY_SIGNATURE 为签名（≤8 KiB）。
     */
    @NotBlank(message = "设备证明不能为空")
    @Size(max = 24576, message = "设备证明超过长度上限")
    private String proof;

    /**
     * 单次随机串的传输编码：调用方生成随机字节后做标准 Base64（车端 SEC/ACC 均为 {@code Base64(32B)}）；
     * VIAM 一次性消费；长度 16～128。KEY_SIGNATURE 的签名对象为解码后的原始字节，不是本字段文本。
     */
    @NotBlank(message = "nonce不能为空")
    @Size(min = 16, max = 128, message = "nonce长度非法（16～128）")
    private String nonce;

    /** 设备标识线索（可选；通常为 deviceSn，证书设备亦可为 hsmUid），仅用于主体定位 */
    @Size(max = 128, message = "设备标识长度非法")
    private String deviceId;
}
