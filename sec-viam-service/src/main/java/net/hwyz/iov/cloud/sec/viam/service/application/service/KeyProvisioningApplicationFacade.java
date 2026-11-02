package net.hwyz.iov.cloud.sec.viam.service.application.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;
import net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamAuthenticatedDeviceContext;
import net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamKeyProvisioningAckRequest;
import net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamKeyProvisioningAckResult;
import net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamKeyProvisioningError;
import net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamKeyProvisioningOutcome;
import net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamKeyProvisioningRequest;
import net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamKeyProvisioningResponse;
import net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamKeyProvisioningStatusRequest;
import net.hwyz.iov.cloud.sec.viam.api.vo.keyprov.ViamKeyProvisioningStatusResponse;
import net.hwyz.iov.cloud.sec.viam.service.common.util.ViamUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Set;

/**
 * Keyprov Service 应用门面（SEC-VIAM-DSN-CR-001 / FR-VIAM-003 / D-VIAM-004）
 * <p>
 * 承接 Adapter 映射后的可信上下文与 canonical payload，完成协议门禁（端点/payloadType/
 * schemaVersion/digest/大小）、canonical 解析、身份与调用方校验，并按端点路由至既有
 * 业务密钥开通/ACK/状态查询应用服务；同时将领域协议错误映射为登记后的 702xxx 稳定错误。
 * <p>
 * 本门面不持有 Wrapped Key 之外的敏感材料，禁止对 payload bytes 执行 toString/日志化。
 * 结果未知（Provider 调用结果未知）禁止自动重放，转对账。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class KeyProvisioningApplicationFacade {

    private static final String REQUEST_PAYLOAD_TYPE = "security.keyprov.v1.KeyProvisioningRequest";
    private static final String ACK_PAYLOAD_TYPE = "security.keyprov.v1.KeyProvisioningAck";
    private static final String STATUS_PAYLOAD_TYPE = "security.keyprov.v1.KeyProvisioningStatusRequest";
    private static final String SCHEMA_VERSION = "keyprov-v1";
    private static final int MAX_PAYLOAD_BYTES = 64 * 1024;
    private static final Set<String> ALLOWED_PROTOCOL_RELEASES =
            Set.of("par-proto-release-2026-10", "par-proto-release-2026-11");

    private final BusinessKeyProvisioningAppService provisioningAppService;

    @Value("${viam.crypto.provisioning.enabled:false}")
    private boolean keyprovEnabled;

    /**
     * 业务密钥开通申请。
     */
    public ViamKeyProvisioningResponse request(ViamKeyProvisioningRequest request) {
        if (!keyprovEnabled) {
            return unavailable("Keyprov能力未启用（fail-closed）");
        }
        // 协议门禁
        if (request == null || request.getPayloadBytes() == null
                || !REQUEST_PAYLOAD_TYPE.equals(request.getPayloadType())
                || !SCHEMA_VERSION.equals(request.getSchemaVersion())) {
            return rejected(ViamErrorCode.KEYPROV_REQUEST_INVALID.getCode(), "Keyprov请求协议校验失败");
        }
        if (request.getPayloadBytes().length > MAX_PAYLOAD_BYTES) {
            return rejected(ViamErrorCode.KEYPROV_REQUEST_INVALID.getCode(), "Keyprov请求超过大小上限");
        }
        // 摘要校验
        String digest = sha256Hex(request.getPayloadBytes());
        if (request.getPayloadDigest() != null && !request.getPayloadDigest().equalsIgnoreCase(digest)) {
            return rejected(ViamErrorCode.KEYPROV_ENVELOPE_INTEGRITY_FAILED.getCode(), "Keyprov请求摘要不一致");
        }
        if (!isAllowedProtocolRelease(request.getProtocolRelease(), request.getDescriptorSetHash())) {
            return rejected(ViamErrorCode.KEYPROV_REQUEST_INVALID.getCode(), "PAR-PROTO release/DescriptorSet未登记");
        }
        try {
            ViamKeyProvisioningResponse response = provisioningAppService.request(
                    request.getDeviceContext(), request.getPayloadBytes(), digest);
            if (response == null) {
                return unavailable("业务密钥开通服务未就绪");
            }
            return response;
        } catch (Exception e) {
            log.warn("Keyprov request失败: context={}, err={}", contextDigest(request.getDeviceContext()), e.getMessage());
            return rejected(mapErrorCode(e), e.getMessage());
        }
    }

    /**
     * 设备导入 ACK（真实验签在业务应用服务内完成）。
     */
    public ViamKeyProvisioningAckResult ack(ViamKeyProvisioningAckRequest request) {
        if (!keyprovEnabled) {
            return ackUnavailable("Keyprov能力未启用（fail-closed）");
        }
        if (request == null || request.getPayloadBytes() == null
                || !ACK_PAYLOAD_TYPE.equals(request.getPayloadType())
                || !SCHEMA_VERSION.equals(request.getSchemaVersion())) {
            return ackRejected(ViamErrorCode.KEYPROV_REQUEST_INVALID.getCode(), "Keyprov ACK协议校验失败");
        }
        String digest = sha256Hex(request.getPayloadBytes());
        if (request.getPayloadDigest() != null && !request.getPayloadDigest().equalsIgnoreCase(digest)) {
            return ackRejected(ViamErrorCode.KEYPROV_ENVELOPE_INTEGRITY_FAILED.getCode(), "Keyprov ACK摘要不一致");
        }
        try {
            ViamKeyProvisioningAckResult result = provisioningAppService.ack(
                    request.getDeviceContext(), request.getPayloadBytes(), digest);
            if (result == null) {
                return ackUnavailable("业务密钥开通服务未就绪");
            }
            return result;
        } catch (Exception e) {
            log.warn("Keyprov ack失败: err={}", e.getMessage());
            return ackRejected(mapErrorCode(e), e.getMessage());
        }
    }

    /**
     * 状态查询（只读，不创建版本、不重放请求）。
     */
    public ViamKeyProvisioningStatusResponse status(ViamKeyProvisioningStatusRequest request) {
        if (!keyprovEnabled) {
            return statusUnavailable("Keyprov能力未启用（fail-closed）");
        }
        if (request == null || request.getPayloadBytes() == null
                || !STATUS_PAYLOAD_TYPE.equals(request.getPayloadType())
                || !SCHEMA_VERSION.equals(request.getSchemaVersion())) {
            return statusRejected(ViamErrorCode.KEYPROV_REQUEST_INVALID.getCode(), "Keyprov状态查询协议校验失败");
        }
        String digest = sha256Hex(request.getPayloadBytes());
        if (request.getPayloadDigest() != null && !request.getPayloadDigest().equalsIgnoreCase(digest)) {
            return statusRejected(ViamErrorCode.KEYPROV_ENVELOPE_INTEGRITY_FAILED.getCode(), "Keyprov状态查询摘要不一致");
        }
        try {
            ViamKeyProvisioningStatusResponse response = provisioningAppService.status(
                    request.getDeviceContext(), request.getPayloadBytes(), digest);
            if (response == null) {
                return statusUnavailable("业务密钥开通服务未就绪");
            }
            return response;
        } catch (Exception e) {
            log.warn("Keyprov status失败: err={}", e.getMessage());
            return statusRejected(mapErrorCode(e), e.getMessage());
        }
    }

    private String mapErrorCode(Exception e) {
        if (e instanceof net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException vse) {
            return vse.getCode();
        }
        if (e instanceof net.hwyz.iov.cloud.sec.viam.service.application.service.keyprov.KeyprovEnvelopeException) {
            return ViamErrorCode.KEYPROV_ENVELOPE_INTEGRITY_FAILED.getCode();
        }
        return ViamErrorCode.KEYPROV_REQUEST_INVALID.getCode();
    }

    private boolean isAllowedProtocolRelease(String protocolRelease, String descriptorSetHash) {
        if (protocolRelease == null || descriptorSetHash == null) {
            return false;
        }
        return ALLOWED_PROTOCOL_RELEASES.contains(protocolRelease.trim());
    }

    private static String contextDigest(ViamAuthenticatedDeviceContext context) {
        if (context == null || context.getHsmUid() == null) {
            return null;
        }
        return ViamUtils.sha256Hex(context.getHsmUid()).substring(0, 12);
    }

    private static String sha256Hex(byte[] bytes) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(bytes));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private ViamKeyProvisioningResponse rejected(String code, String message) {
        return ViamKeyProvisioningResponse.builder()
                .outcome(ViamKeyProvisioningOutcome.REJECTED)
                .error(ViamKeyProvisioningError.builder().code(code).message(message)
                        .retryable(false).action("DO_NOT_RETRY").build())
                .build();
    }

    private ViamKeyProvisioningResponse unavailable(String message) {
        return ViamKeyProvisioningResponse.builder()
                .outcome(ViamKeyProvisioningOutcome.UNAVAILABLE)
                .error(ViamKeyProvisioningError.builder()
                        .code(ViamErrorCode.BUSINESS_KEY_KMS_UNAVAILABLE.getCode())
                        .message(message).retryable(true).action("RETRY_SAME_REQUEST_ID").build())
                .build();
    }

    private ViamKeyProvisioningAckResult ackRejected(String code, String message) {
        return ViamKeyProvisioningAckResult.builder()
                .outcome(ViamKeyProvisioningOutcome.REJECTED)
                .error(ViamKeyProvisioningError.builder().code(code).message(message)
                        .retryable(false).action("DO_NOT_RETRY").build())
                .build();
    }

    private ViamKeyProvisioningAckResult ackUnavailable(String message) {
        return ViamKeyProvisioningAckResult.builder()
                .outcome(ViamKeyProvisioningOutcome.UNAVAILABLE)
                .error(ViamKeyProvisioningError.builder()
                        .code(ViamErrorCode.BUSINESS_KEY_KMS_UNAVAILABLE.getCode())
                        .message(message).retryable(true).action("RETRY_SAME_REQUEST_ID").build())
                .build();
    }

    private ViamKeyProvisioningStatusResponse statusRejected(String code, String message) {
        return ViamKeyProvisioningStatusResponse.builder()
                .outcome(ViamKeyProvisioningOutcome.REJECTED)
                .error(ViamKeyProvisioningError.builder().code(code).message(message)
                        .retryable(false).action("DO_NOT_RETRY").build())
                .build();
    }

    private ViamKeyProvisioningStatusResponse statusUnavailable(String message) {
        return ViamKeyProvisioningStatusResponse.builder()
                .outcome(ViamKeyProvisioningOutcome.UNAVAILABLE)
                .error(ViamKeyProvisioningError.builder()
                        .code(ViamErrorCode.BUSINESS_KEY_KMS_UNAVAILABLE.getCode())
                        .message(message).retryable(true).action("QUERY_STATUS_LATER").build())
                .build();
    }
}
