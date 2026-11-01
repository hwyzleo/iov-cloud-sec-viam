package net.hwyz.iov.cloud.sec.viam.service.application.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import net.hwyz.iov.cloud.sec.viam.service.common.util.ViamUtils;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.PrincipalAssetMapping;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SecurityPrincipal;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.PrincipalAssetMappingRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.SecurityPrincipalRepository;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.vmd.VmdBindingFactAdapter;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

/**
 * 安全主体应用服务（SEC-VIAM-DSN-CR-001 / FR-VIAM-001 / D-VIAM-003）
 * <p>
 * 建立稳定 principalId 与设备资产键/VIN 分开的安全主体模型；身份关联由受信入站登记、
 * VMD 事实和迁入凭据记录建立，不得仅信客户端自报 UID。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SecurityPrincipalAppService {

    private final SecurityPrincipalRepository principalRepository;
    private final PrincipalAssetMappingRepository mappingRepository;
    private final VmdBindingFactAdapter vmdBindingFactAdapter;

    /**
     * 受信入站登记安全主体（来源系统/凭据记录登记，非客户端自报）。
     *
     * @param hsmUid       权威 HSM UID
     * @param sourceSystem 登记来源系统
     * @param sourceRefId  来源引用
     * @return 主体
     */
    @Transactional(rollbackFor = Exception.class)
    public SecurityPrincipal registerPrincipal(String hsmUid, String sourceSystem, String sourceRefId) {
        String normalized = ViamUtils.normalizeUid(hsmUid);
        if (normalized == null) {
            throw new ViamServiceException(ViamErrorCode.PRINCIPAL_UID_UNAVAILABLE);
        }
        if (!isTrustedSource(sourceSystem)) {
            throw new ViamServiceException(ViamErrorCode.PRINCIPAL_REGISTRATION_NOT_TRUSTED);
        }
        SecurityPrincipal existing = principalRepository.findByHsmUid(normalized).orElse(null);
        if (existing != null) {
            return existing;
        }
        SecurityPrincipal principal = SecurityPrincipal.builder()
                .principalId(ViamUtils.newPrincipalId(normalized))
                .hsmUid(normalized)
                .sourceSystem(sourceSystem)
                .sourceRefId(sourceRefId)
                .state(SecurityPrincipal.PrincipalState.ACTIVE)
                .createdAt(Instant.now())
                .build();
        principalRepository.save(principal);
        log.info("安全主体登记: principalId={}, sourceSystem={}", principal.getPrincipalId(), sourceSystem);
        return principal;
    }

    /**
     * 受信入站登记：建立安全主体与资产的映射（不恢复 VMD 绑定写入口）。
     * <p>
     * 仅受信来源（VMD 事实/迁移/管理导入/OAPI 受信登记）可建立映射；
     * 客户端自报 UID 不得作为关联依据（D-VIAM-003 / FR-VIAM-001）。
     * </p>
     *
     * @param principalId 安全主体ID
     * @param vin         车辆VIN
     * @param deviceSn    设备物理实例序列号
     * @param bindingId   绑定ID（VMD 事实）
     * @param partId      零件实例ID
     * @param deviceCategory 设备类别
     * @param bindingVersion 绑定版本
     * @param bindingUpdatedAt 绑定更新时间
     */
    @Transactional(rollbackFor = Exception.class)
    public void registerAssetMapping(String principalId, String vin, String deviceSn, Long bindingId,
                                     Long partId, String deviceCategory, Long bindingVersion,
                                     java.time.Instant bindingUpdatedAt) {
        SecurityPrincipal principal = principalRepository.findByPrincipalId(principalId)
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.PRINCIPAL_NOT_EXIST));
        if (principal.getState() != SecurityPrincipal.PrincipalState.ACTIVE) {
            throw new ViamServiceException(ViamErrorCode.PRINCIPAL_ASSET_MAPPING_CONFLICT);
        }
        PrincipalAssetMapping mapping = PrincipalAssetMapping.builder()
                .principalId(principalId)
                .vin(vin)
                .deviceSn(deviceSn)
                .bindingId(bindingId)
                .partId(partId)
                .bindingVersion(bindingVersion)
                .bindingUpdatedAt(bindingUpdatedAt)
                .deviceCategory(deviceCategory)
                .state(PrincipalAssetMapping.MappingState.ACTIVE)
                .build();
        mappingRepository.save(mapping);
        log.info("安全主体资产映射登记: principalId={}, vin={}, deviceSn={}", principalId, vin, deviceSn);
    }

    /**
     * 同步 VMD 绑定事实到资产映射（只读投影，不反向修改 VMD）。
     * <p>
     * 身份关联由受信入站登记建立（principal ↔ asset 映射已存在）；此处仅以 VMD 事实
     * 同步绑定版本/设备类别等投影字段，不以 VMD 绑定 DTO 的 sn 猜测 hsmUid（D-VIAM-003）。
     * </p>
     */
    @Transactional(rollbackFor = Exception.class)
    public void syncBindingFacts(String vin) {
        List<net.hwyz.iov.cloud.edd.vmd.api.vo.response.VehiclePartBindingExResponse> bindings =
                vmdBindingFactAdapter.listActiveBindingsByVin(vin);
        for (net.hwyz.iov.cloud.edd.vmd.api.vo.response.VehiclePartBindingExResponse binding : bindings) {
            // 已由受信登记建立的资产映射（按设备SN匹配；SN 仅资产追溯，非身份）
            PrincipalAssetMapping mapping = mappingRepository.findActiveByDeviceSn(binding.getSn()).orElse(null);
            if (mapping == null) {
                // VMD 绑定 DTO 不足以提供 UID：不猜测、不自动登记主体，等待受信入站登记/迁入凭据
                log.warn("VMD绑定无受信登记的资产映射，跳过投影同步（等待受信登记）: sn={}, vin={}",
                        binding.getSn(), binding.getVin());
                continue;
            }
            // 仅同步投影字段（绑定版本/设备类别/更新时间），不修改主体身份
            mapping.syncBindingFact(binding.getBindingId() == null ? mapping.getBindingVersion() : 1L,
                    binding.getBindTime());
            mapping.setDeviceCategory(binding.getDeviceCategory());
            mappingRepository.save(mapping);
        }
    }

    /**
     * 按 VIN 解析接入身份。
     */
    public SecurityPrincipal resolvePrincipalByVin(String vin) {
        List<PrincipalAssetMapping> mappings = mappingRepository.listActiveByVin(vin);
        if (mappings.size() != 1) {
            throw new ViamServiceException(ViamErrorCode.PRINCIPAL_ASSET_MAPPING_CONFLICT);
        }
        return principalRepository.findByPrincipalId(mappings.get(0).getPrincipalId())
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.PRINCIPAL_NOT_EXIST));
    }

    /**
     * 受信来源判定（受信入站登记/迁移/管理导入）。
     */
    private boolean isTrustedSource(String sourceSystem) {
        if (sourceSystem == null) {
            return false;
        }
        switch (sourceSystem.toUpperCase()) {
            case "VMD_FACT":
            case "MIGRATION":
            case "OAPI_TRUSTED":
            case "MPT_ADMIN":
                return true;
            default:
                return false;
        }
    }
}
