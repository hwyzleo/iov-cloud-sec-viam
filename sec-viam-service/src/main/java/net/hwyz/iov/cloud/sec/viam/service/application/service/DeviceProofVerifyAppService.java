package net.hwyz.iov.cloud.sec.viam.service.application.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;
import net.hwyz.iov.cloud.sec.viam.api.vo.DeviceProofVerifyRequestVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.DeviceProofVerifyResultVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.enums.DeviceProofReasonCode;
import net.hwyz.iov.cloud.sec.viam.api.vo.enums.DeviceProofType;
import net.hwyz.iov.cloud.sec.viam.api.vo.enums.DeviceStatus;
import net.hwyz.iov.cloud.sec.viam.service.application.service.deviceproof.DeviceProofAuditRecorder;
import net.hwyz.iov.cloud.sec.viam.service.application.service.deviceproof.DeviceProofMetrics;
import net.hwyz.iov.cloud.sec.viam.service.application.service.deviceproof.DeviceProofNonceStore;
import net.hwyz.iov.cloud.sec.viam.service.application.service.deviceproof.DeviceProofProperties;
import net.hwyz.iov.cloud.sec.viam.service.application.service.deviceproof.DeviceProofRateLimiter;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.DeviceProofDependencyException;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.DeviceProofInvalidException;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import net.hwyz.iov.cloud.sec.viam.service.common.util.ViamUtils;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.DeviceOnboarding;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.PrincipalAssetMapping;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SecurityPrincipal;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.port.DeviceProofEvidence;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.port.DeviceProofVerifier;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.DeviceOnboardingRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.PrincipalAssetMappingRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.SecurityPrincipalRepository;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * 设备证明校验应用服务（SEC-VIAM-DSN-CR-003 / FR-VIAM-3-1～3-8）
 * <p>
 * 供 CIAM 在签发 IVI 设备令牌前确认设备身份与可用性。编排顺序固定为：
 * 能力开关 → 参数语义 → 限流（调用方+设备）→ nonce 一次性 → 证明校验（PKI）→
 * 主体定位与交叉校验 → 安全状态 → 结论映射 → 审计与指标。
 * </p>
 * <ul>
 *   <li>只读幂等：不写设备状态、不签发凭据、不改证书目录（D-VIAM-3-05）。</li>
 *   <li>四类结论显式区分；依赖不可用一律 fail-closed 返回 {@code DEPENDENCY_UNAVAILABLE}（D-VIAM-3-03/07）。</li>
 *   <li>脱敏：日志/审计只含摘要与结论，不含证书、签名、nonce 原文或完整 deviceId（D-VIAM-3-06）。</li>
 *   <li>不返回 VIN、不附带绑定信息（D-VIAM-3-08）。</li>
 * </ul>
 *
 * @author hwyz_leo
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DeviceProofVerifyAppService {

    /** 证明体 Base64 长度上限（与请求VO一致：16 KiB 二进制 → ≤22 KiB Base64） */
    private static final int MAX_PROOF_BASE64_LENGTH = 24 * 1024;

    private final DeviceProofVerifier deviceProofVerifier;
    private final SecurityPrincipalRepository principalRepository;
    private final PrincipalAssetMappingRepository mappingRepository;
    private final DeviceOnboardingRepository onboardingRepository;
    private final DeviceProofNonceStore nonceStore;
    private final DeviceProofRateLimiter rateLimiter;
    private final DeviceProofAuditRecorder auditRecorder;
    private final DeviceProofMetrics metrics;
    private final DeviceProofProperties properties;

    /**
     * 校验设备证明（只读、幂等、无业务写副作用）。
     *
     * @param request 证明请求
     * @param caller  调用方服务身份（X-Client-Id 自报，供审计/限流识别；缺失记 UNKNOWN）
     * @return 结论（valid + reasonCode + 已登记主体事实）
     */
    public DeviceProofVerifyResultVo verify(DeviceProofVerifyRequestVo request, String caller) {
        Instant verifiedAt = Instant.now();
        long startNanos = System.nanoTime();
        String requestId = "DP-" + UUID.randomUUID().toString().replace("-", "");
        String callerId = normalizeCaller(caller);

        // 1. 能力开关：未启用视为不可用（fail-closed），绝不返回通过
        if (!properties.isEnabled()) {
            return reject(requestId, callerId, null, request, DeviceProofReasonCode.DEPENDENCY_UNAVAILABLE,
                    ViamErrorCode.PROOF_DEPENDENCY_UNAVAILABLE, verifiedAt, startNanos, "设备证明校验能力未启用");
        }

        // 2. 参数语义（缺失/格式非法走框架参数错误语义，702720）
        DeviceProofType proofType = DeviceProofType.valOf(request.getProofType());
        if (proofType == null) {
            throw new ViamServiceException(ViamErrorCode.PROOF_VERIFY_PARAM_INVALID,
                    "不支持的证明类型: " + request.getProofType());
        }
        byte[] proofBytes = decodeProof(request.getProof());
        if (isBlank(request.getNonce())) {
            throw new ViamServiceException(ViamErrorCode.PROOF_VERIFY_PARAM_INVALID, "nonce不能为空");
        }
        if (proofType == DeviceProofType.KEY_SIGNATURE && isBlank(request.getDeviceId())) {
            throw new ViamServiceException(ViamErrorCode.PROOF_VERIFY_PARAM_INVALID,
                    "KEY_SIGNATURE 证明必须携带 deviceId（通常为 deviceSn）");
        }
        if (elapsed(startNanos).compareTo(budget()) > 0) {
            return reject(requestId, callerId, null, request, DeviceProofReasonCode.DEPENDENCY_UNAVAILABLE,
                    ViamErrorCode.PROOF_DEPENDENCY_UNAVAILABLE, verifiedAt, startNanos, "参数处理超出总预算");
        }

        // 3. 限流（调用方 + 设备维度；防止证明爆破）
        try {
            if (!rateLimiter.tryAcquire(callerId, request.getDeviceId(), verifiedAt)) {
                metrics.recordRateLimited();
                return reject(requestId, callerId, null, request, DeviceProofReasonCode.RATE_LIMITED,
                        ViamErrorCode.PROOF_RATE_LIMITED, verifiedAt, startNanos, "调用频次超限");
            }
        } catch (DeviceProofDependencyException e) {
            return reject(requestId, callerId, null, request, DeviceProofReasonCode.DEPENDENCY_UNAVAILABLE,
                    ViamErrorCode.PROOF_DEPENDENCY_UNAVAILABLE, verifiedAt, startNanos, "限流依赖不可用");
        }

        // 4. nonce 一次性校验（先消费、不回滚：防重放优先）
        try {
            if (!nonceStore.consume(request.getNonce())) {
                metrics.recordNonceReplay();
                return reject(requestId, callerId, null, request, DeviceProofReasonCode.PROOF_INVALID,
                        ViamErrorCode.PROOF_NONCE_REPLAYED, verifiedAt, startNanos, "nonce已消费（重放）");
            }
        } catch (DeviceProofDependencyException e) {
            return reject(requestId, callerId, null, request, DeviceProofReasonCode.DEPENDENCY_UNAVAILABLE,
                    ViamErrorCode.PROOF_DEPENDENCY_UNAVAILABLE, verifiedAt, startNanos, "nonce存储依赖不可用");
        }

        // 5. 证明解析与校验（证书链/有效期/吊销/指纹/签名；依赖不可用不伪装为吊销）
        DeviceProofEvidence evidence;
        try {
            evidence = deviceProofVerifier.verify(proofType, proofBytes, request.getNonce(),
                    request.getDeviceId(), verifiedAt);
        } catch (DeviceProofInvalidException e) {
            return reject(requestId, callerId, null, request, DeviceProofReasonCode.PROOF_INVALID,
                    ViamErrorCode.PROOF_INVALID, verifiedAt, startNanos, e.getMessage());
        } catch (DeviceProofDependencyException e) {
            return reject(requestId, callerId, null, request, DeviceProofReasonCode.DEPENDENCY_UNAVAILABLE,
                    ViamErrorCode.PROOF_DEPENDENCY_UNAVAILABLE, verifiedAt, startNanos, e.getMessage());
        } catch (RuntimeException e) {
            log.warn("设备证明校验异常，fail-closed: requestId={}, err={}", requestId, e.getClass().getSimpleName());
            return reject(requestId, callerId, null, request, DeviceProofReasonCode.DEPENDENCY_UNAVAILABLE,
                    ViamErrorCode.PROOF_DEPENDENCY_UNAVAILABLE, verifiedAt, startNanos, "证明校验异常");
        }
        if (elapsed(startNanos).compareTo(budget()) > 0) {
            return reject(requestId, callerId, null, request, DeviceProofReasonCode.DEPENDENCY_UNAVAILABLE,
                    ViamErrorCode.PROOF_DEPENDENCY_UNAVAILABLE, verifiedAt, startNanos, "证明校验超出总预算");
        }

        // 6. 主体定位（以 VIAM 已登记事实为准，不取调用方声明）
        SecurityPrincipal principal = principalRepository.findByHsmUid(evidence.hsmUid()).orElse(null);
        if (principal == null) {
            return reject(requestId, callerId, null, request, DeviceProofReasonCode.SUBJECT_UNAVAILABLE,
                    ViamErrorCode.PROOF_SUBJECT_UNAVAILABLE, verifiedAt, startNanos, "设备安全主体未登记");
        }
        List<PrincipalAssetMapping> mappings = activeMappings(principal.getPrincipalId());
        String deviceSn = resolveDeviceSn(evidence, mappings);
        if (!deviceIdConsistent(request.getDeviceId(), evidence.hsmUid(), deviceSn, mappings)) {
            return reject(requestId, callerId, principal.getPrincipalId(), request,
                    DeviceProofReasonCode.PROOF_INVALID, ViamErrorCode.PROOF_INVALID, verifiedAt, startNanos,
                    "证明主体与deviceId线索不一致");
        }
        if (principal.getState() != SecurityPrincipal.PrincipalState.ACTIVE) {
            return reject(requestId, callerId, principal.getPrincipalId(), request,
                    DeviceProofReasonCode.SUBJECT_UNAVAILABLE, ViamErrorCode.PROOF_SUBJECT_UNAVAILABLE,
                    verifiedAt, startNanos, "设备安全主体状态不可用: " + principal.getState());
        }
        DeviceOnboarding onboarding = onboardingRepository.findByPrincipalId(principal.getPrincipalId()).orElse(null);
        if (onboarding != null && (onboarding.getState() == DeviceOnboarding.OnboardingState.BLOCKED
                || onboarding.getState() == DeviceOnboarding.OnboardingState.RETIRED)) {
            return reject(requestId, callerId, principal.getPrincipalId(), request,
                    DeviceProofReasonCode.SUBJECT_UNAVAILABLE, ViamErrorCode.PROOF_SUBJECT_UNAVAILABLE,
                    verifiedAt, startNanos, "设备安全开通状态不可用: " + onboarding.getState());
        }

        // 7. 通过：只返回认证结论与已登记事实（不含 VIN/绑定信息）
        String deviceStatus = onboarding == null
                ? DeviceStatus.PRE_ACTIVE.name() : onboarding.getState().name();
        return accept(requestId, callerId, principal.getPrincipalId(), deviceSn, deviceStatus,
                request, verifiedAt, startNanos);
    }

    private DeviceProofVerifyResultVo accept(String requestId, String callerId, String principalId,
                                             String deviceSn, String deviceStatus,
                                             DeviceProofVerifyRequestVo request, Instant verifiedAt,
                                             long startNanos) {
        finish(requestId, callerId, principalId, request, DeviceProofReasonCode.PROOF_VALID,
                null, verifiedAt, startNanos);
        return DeviceProofVerifyResultVo.valid(principalId, deviceSn, deviceStatus, verifiedAt);
    }

    private DeviceProofVerifyResultVo reject(String requestId, String callerId, String principalId,
                                             DeviceProofVerifyRequestVo request, DeviceProofReasonCode reasonCode,
                                             ViamErrorCode errorCode, Instant verifiedAt, long startNanos,
                                             String detail) {
        finish(requestId, callerId, principalId, request, reasonCode, errorCode, verifiedAt, startNanos);
        log.info("VIAM设备证明校验拒绝: requestId={}, caller={}, proofType={}, reason={}, code={}, detail={}",
                requestId, callerId, request.getProofType(), reasonCode,
                errorCode == null ? null : errorCode.getCode(), detail);
        return DeviceProofVerifyResultVo.rejected(reasonCode, verifiedAt);
    }

    private void finish(String requestId, String callerId, String principalId,
                        DeviceProofVerifyRequestVo request, DeviceProofReasonCode reasonCode,
                        ViamErrorCode errorCode, Instant verifiedAt, long startNanos) {
        Duration elapsed = elapsed(startNanos);
        metrics.recordVerify(reasonCode.name(), reasonCode == DeviceProofReasonCode.PROOF_VALID, elapsed);
        auditRecorder.record(requestId, callerId, principalId, request.getProofType(),
                ViamUtils.sha256Hex(request.getProof()), ViamUtils.sha256Hex(request.getNonce()),
                request.getDeviceId(), reasonCode.name(),
                errorCode == null ? null : errorCode.getCode(), elapsed.toMillis(), verifiedAt);
        if (reasonCode == DeviceProofReasonCode.PROOF_VALID) {
            log.info("VIAM设备证明校验通过: requestId={}, caller={}, proofType={}, principalDigest={}, time={}ms",
                    requestId, callerId, request.getProofType(), ViamUtils.sha256Hex(principalId), elapsed.toMillis());
        }
    }

    private List<PrincipalAssetMapping> activeMappings(String principalId) {
        try {
            return mappingRepository.listActiveByPrincipalId(principalId);
        } catch (RuntimeException e) {
            log.warn("资产映射读取失败（不影响证明结论）: principalDigest={}", ViamUtils.sha256Hex(principalId));
            return List.of();
        }
    }

    private static String resolveDeviceSn(DeviceProofEvidence evidence, List<PrincipalAssetMapping> mappings) {
        if (mappings != null) {
            for (PrincipalAssetMapping mapping : mappings) {
                if (mapping.getDeviceSn() != null && !mapping.getDeviceSn().isBlank()) {
                    return mapping.getDeviceSn();
                }
            }
        }
        return evidence.deviceSn();
    }

    private static boolean deviceIdConsistent(String deviceId, String hsmUid, String deviceSn,
                                              List<PrincipalAssetMapping> mappings) {
        if (deviceId == null || deviceId.isBlank()) {
            return true;
        }
        String claimed = deviceId.trim();
        if (hsmUid != null && hsmUid.equalsIgnoreCase(claimed)) {
            return true;
        }
        if (deviceSn != null && deviceSn.equals(claimed)) {
            return true;
        }
        if (mappings != null) {
            for (PrincipalAssetMapping mapping : mappings) {
                if (mapping.getDeviceSn() != null && mapping.getDeviceSn().equals(claimed)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static byte[] decodeProof(String proof) {
        if (isBlank(proof)) {
            throw new ViamServiceException(ViamErrorCode.PROOF_VERIFY_PARAM_INVALID, "证明体不能为空");
        }
        if (proof.length() > MAX_PROOF_BASE64_LENGTH) {
            throw new ViamServiceException(ViamErrorCode.PROOF_VERIFY_PARAM_INVALID, "证明体超过长度上限");
        }
        try {
            return Base64.getDecoder().decode(proof.trim());
        } catch (IllegalArgumentException e) {
            throw new ViamServiceException(ViamErrorCode.PROOF_VERIFY_PARAM_INVALID, "证明体不是合法Base64");
        }
    }

    private Duration budget() {
        Duration total = properties.getVerify() == null ? null : properties.getVerify().getTotalBudget();
        return total == null ? Duration.ofSeconds(1) : total;
    }

    private static Duration elapsed(long startNanos) {
        return Duration.ofNanos(System.nanoTime() - startNanos);
    }

    private static String normalizeCaller(String caller) {
        return caller == null || caller.isBlank() ? "UNKNOWN" : caller.trim();
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
