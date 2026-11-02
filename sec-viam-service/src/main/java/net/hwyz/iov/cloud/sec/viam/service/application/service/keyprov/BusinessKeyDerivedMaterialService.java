package net.hwyz.iov.cloud.sec.viam.service.application.service.keyprov;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKey;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import net.hwyz.iov.cloud.sec.viam.service.common.util.ViamUtils;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.DeviceBusinessKey;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.DeviceBusinessKeyRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Objects;

/**
 * 根派生材料落库与 claim-or-reuse（迁入 VMD 既有实现，适配 VIAM 目录模型）。
 * <p>
 * 目录行（DeviceBusinessKey）保存 Provider 返回的非敏感材料状态（keyId/kmsKeyRef/
 * rootKeyVersion/derivationVersion/operationId/算法/有效期/逻辑身份摘要）；
 * 撞 keyId 时做<strong>确定性 claim-or-reuse</strong>：不可变身份完全一致后复用，
 * 否则 {@link ViamServiceException}（不可重试 + 告警）。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class BusinessKeyDerivedMaterialService {

    private static final String MATERIAL_MODEL_DERIVED_ROOT = "DERIVED_ROOT";

    private final DeviceBusinessKeyRepository businessKeyRepository;

    /**
     * 身份一致性校验上下文（非敏感）。
     */
    public record ClaimContext(String deviceSn, String businessDomain, String purpose,
                               String bizType, String normalizedAnchor, String requestId) {
    }

    /**
     * 回填/复用根派生材料（claim-or-reuse）。
     *
     * @param row   目标目录行（可为 PENDING 或已有 keyId）
     * @param result Provider 派生封装结果
     * @param policy 授权/密码学策略（算法/规格/有效期）
     * @param operationId 操作标识
     * @param ctx    身份一致性上下文
     * @return canonical 目录行
     */
    @Transactional(rollbackFor = Exception.class)
    public DeviceBusinessKey persistOrClaimDerivedMaterial(DeviceBusinessKey row, DerivedWrappedKey result,
                                                           BusinessKeyPolicy policy, String operationId,
                                                           ClaimContext ctx) {
        if (row.getKeyId() != null && !row.getKeyId().equals(result.logicalKeyId())) {
            throw conflict("key_id_mismatch",
                    "占位行 keyId 与 Provider 结果不一致: " + row.getKeyId() + " vs " + result.logicalKeyId());
        }
        DeviceBusinessKey existing = businessKeyRepository.findByKeyId(result.logicalKeyId()).orElse(null);
        if (existing == null) {
            // 首次 attach：回填材料状态
            attach(row, result, policy, operationId, ctx);
            return row;
        }
        // claim-or-reuse：身份一致性校验后复用 canonical 行
        verifySameLogicalIdentity(existing, result, policy, ctx);
        ensureDirectoryValidity(existing, policy);
        recoverIfNeeded(existing, ctx);
        log.info("keyprov 目录材料 claim-or-reuse 收敛: requestId={}, purpose={}, keyId={}, state={}",
                ctx.requestId(), ctx.purpose(), existing.getKeyId(), existing.getKeyState());
        return existing;
    }

    private void attach(DeviceBusinessKey row, DerivedWrappedKey result, BusinessKeyPolicy policy,
                        String operationId, ClaimContext ctx) {
        Instant now = Instant.now();
        row.setKeyId(result.logicalKeyId());
        row.setKmsKeyRef(result.kmsKeyRef());
        row.setMaterialModel(MATERIAL_MODEL_DERIVED_ROOT);
        row.setRootKeyVersion(result.rootKeyVersion());
        row.setDerivationVersion(result.derivationVersion());
        row.setOperationId(result.operationId() != null ? result.operationId() : operationId);
        row.setAlgorithm(policy.algorithm());
        row.setKeySpec(policy.keySpec());
        row.setValidFrom(now);
        row.setValidTo(now.plus(policy.validitySeconds(), ChronoUnit.SECONDS));
        row.setPolicyVersion(policy.policyVersion());
        row.setLogicalIdentityDigest(ViamUtils.sha256Hex(
                ctx.bizType() + "|" + ctx.normalizedAnchor() + "|" + ctx.purpose()
                        + "|" + result.rootKeyVersion() + "|" + result.derivationVersion())
                .getBytes(java.nio.charset.StandardCharsets.UTF_8));
        businessKeyRepository.save(row);
    }

    private void ensureDirectoryValidity(DeviceBusinessKey row, BusinessKeyPolicy policy) {
        Instant now = Instant.now();
        if (row.getValidFrom() != null && row.getValidTo() != null
                && row.getValidTo().isAfter(now)) {
            return;
        }
        row.setValidFrom(now);
        row.setValidTo(now.plus(policy.validitySeconds(), ChronoUnit.SECONDS));
        businessKeyRepository.save(row);
    }

    private void recoverIfNeeded(DeviceBusinessKey existing, ClaimContext ctx) {
        DeviceBusinessKey.KeyState state = existing.getKeyState();
        if (state == DeviceBusinessKey.KeyState.ACTIVE || state == DeviceBusinessKey.KeyState.PENDING) {
            return;
        }
        if (state == DeviceBusinessKey.KeyState.FAILED
                || state == DeviceBusinessKey.KeyState.RECONCILE_REQUIRED
                || state == DeviceBusinessKey.KeyState.PENDING_RECOVERY) {
            if (existing.getKeyId() == null) {
                throw conflict("evidence_incomplete", "FAILED/RECONCILE_REQUIRED 行证据不完整，不可恢复");
            }
            existing.setKeyState(DeviceBusinessKey.KeyState.PENDING);
            existing.setLastRecoveryRequestId(ctx.requestId());
            existing.setRecoveryCount(existing.getRecoveryCount() + 1);
            businessKeyRepository.save(existing);
            log.info("keyprov 目录材料恢复复用: requestId={}, purpose={}, rowId={}, fromState={}",
                    ctx.requestId(), ctx.purpose(), existing.getId(), state);
            return;
        }
        throw conflict("state_not_reusable",
                "目录行状态不可复用: state=" + state);
    }

    private void verifySameLogicalIdentity(DeviceBusinessKey existing, DerivedWrappedKey result,
                                           BusinessKeyPolicy policy, ClaimContext ctx) {
        if (!Objects.equals(existing.getDeviceSn(), ctx.deviceSn())
                || !Objects.equals(existing.getBusinessDomain(), ctx.businessDomain())
                || !Objects.equals(existing.getPurpose(), ctx.purpose())) {
            throw conflict("context_mismatch", "同keyId但设备/域/用途上下文不一致: keyId=" + result.logicalKeyId());
        }
        if (existing.getMaterialModel() == null || !MATERIAL_MODEL_DERIVED_ROOT.equals(existing.getMaterialModel())) {
            throw conflict("material_model_mismatch",
                    "既有行材料模型非 DERIVED_ROOT 或来源未知，禁止复用: keyId=" + result.logicalKeyId());
        }
        if (!Objects.equals(existing.getKmsKeyRef(), result.kmsKeyRef())) {
            throw conflict("kms_ref_mismatch", "同keyId但 kmsKeyRef 不一致");
        }
        if (existing.getRootKeyVersion() == null || existing.getRootKeyVersion() != result.rootKeyVersion()) {
            throw conflict("root_mismatch",
                    "同keyId但 rootKeyVersion 不一致: existing=" + existing.getRootKeyVersion()
                            + ", result=" + result.rootKeyVersion());
        }
        if (!Objects.equals(existing.getDerivationVersion(), result.derivationVersion())) {
            throw conflict("derivation_mismatch", "同keyId但 derivationVersion 不一致");
        }
        if (!Objects.equals(existing.getAlgorithm(), policy.algorithm())
                || !Objects.equals(existing.getKeySpec(), policy.keySpec())) {
            throw conflict("algorithm_mismatch", "同keyId但 算法/keySpec 与当前策略不一致");
        }
    }

    private ViamServiceException conflict(String reason, String detail) {
        log.warn("keyprov 逻辑身份冲突: reason={}, detail={}", reason, detail);
        return new ViamServiceException(ViamErrorCode.BUSINESS_KEY_LOGICAL_IDENTITY_CONFLICT, detail);
    }

    /**
     * 授权/密码学策略（V2C 首期固定）。
     */
    public record BusinessKeyPolicy(String algorithm, String keySpec, long validitySeconds, String policyVersion) {

        public static BusinessKeyPolicy v2c() {
            return new BusinessKeyPolicy("AES", "AES-256-GCM", 365L * 24 * 3600, "viam-v2c-v1");
        }
    }
}
