package net.hwyz.iov.cloud.sec.viam.service.application.service;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.edd.vmd.api.vo.response.VehiclePartBindingExResponse;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.PrincipalAssetMapping;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SecurityOperationAudit;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SecurityPrincipal;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.PrincipalAssetMappingRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.SecurityOperationAuditRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * 绑定快照收敛写入器（SEC-VIAM-DSN-CR-006 / D-VIAM-032）
 * <p>
 * 只做“快照 → 主体/映射”的事务内收敛，Feign 快照查询在事务外完成（调用方 {@link BindingFactEnrollmentAppService}）。
 * 收敛规则：
 * <ol>
 *   <li>白名单类别 + 可用芯片 UID → 复用或登记主体，映射 ACTIVE；</li>
 *   <li>同 VIN 同类别已有其他 SN 的 ACTIVE 映射 → SUPERSEDED（换件）；</li>
 *   <li>同 SN 但 bindingId 变化 → 旧映射 SUPERSEDED 后新建 ACTIVE；</li>
 *   <li>快照中已不存在的 ACTIVE 映射 → UNBOUND（不吊销、不触发访问失效）。</li>
 * </ol>
 *
 * @author hwyz_leo
 * @since 2026-11-24
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class BindingFactSnapshotApplier {

    private final SecurityPrincipalAppService securityPrincipalAppService;
    private final PrincipalAssetMappingRepository mappingRepository;
    private final SecurityOperationAuditRepository auditRepository;

    /**
     * 收敛绑定快照
     *
     * @param vin             车架号
     * @param eventId         触发事件ID（审计与幂等线索）
     * @param enrollable      可登记绑定（白名单类别 + 芯片 UID 可用）
     * @param snapshotDeviceSns 快照内全部设备 SN（含因芯片 UID 缺失被跳过者）
     * @param enrollSourceSystem 登记来源系统（受信）
     * @return 收敛结果
     */
    @Transactional(rollbackFor = Exception.class)
    public Outcome apply(String vin, String eventId, List<VehiclePartBindingExResponse> enrollable,
                         Set<String> snapshotDeviceSns, String enrollSourceSystem) {
        List<PrincipalAssetMapping> current = new ArrayList<>(mappingRepository.listActiveByVin(vin));
        Map<String, PrincipalAssetMapping> activeBySn = new LinkedHashMap<>();
        for (PrincipalAssetMapping mapping : current) {
            if (mapping.getState() == PrincipalAssetMapping.MappingState.ACTIVE) {
                activeBySn.put(mapping.getDeviceSn(), mapping);
            }
        }

        Outcome outcome = new Outcome();
        SecurityPrincipal firstPrincipal = null;

        for (VehiclePartBindingExResponse binding : enrollable) {
            String category = normalizeCategory(binding.getDeviceCategory());
            SecurityPrincipal principal = securityPrincipalAppService.registerPrincipal(
                    binding.getChipUid(), enrollSourceSystem, String.valueOf(binding.getBindingId()));
            if (firstPrincipal == null) {
                firstPrincipal = principal;
            }

            PrincipalAssetMapping mapping = activeBySn.get(binding.getSn());
            if (mapping != null && !Objects.equals(mapping.getBindingId(), binding.getBindingId())) {
                // 同 SN 换绑（bindingId 变化）：旧映射退出 ACTIVE，避免唯一索引冲突
                mapping.supersede();
                mappingRepository.save(mapping);
                activeBySn.remove(binding.getSn());
                outcome.superseded++;
                mapping = null;
            }

            // 同 VIN 同类别其他 SN 的 ACTIVE 映射 → SUPERSEDED（换件）
            for (PrincipalAssetMapping other : new ArrayList<>(activeBySn.values())) {
                if (!other.getDeviceSn().equals(binding.getSn())
                        && category.equals(normalizeCategory(other.getDeviceCategory()))) {
                    other.supersede();
                    mappingRepository.save(other);
                    activeBySn.remove(other.getDeviceSn());
                    outcome.superseded++;
                }
            }

            if (mapping == null) {
                PrincipalAssetMapping created = PrincipalAssetMapping.builder()
                        .principalId(principal.getPrincipalId())
                        .vin(binding.getVin() == null ? vin : binding.getVin())
                        .deviceSn(binding.getSn())
                        .bindingId(binding.getBindingId())
                        .partId(null)
                        .bindingVersion(binding.getBindingId())
                        .bindingUpdatedAt(binding.getBindTime())
                        .deviceCategory(category)
                        .state(PrincipalAssetMapping.MappingState.ACTIVE)
                        .build();
                mappingRepository.save(created);
                activeBySn.put(binding.getSn(), created);
                outcome.created++;
            } else {
                boolean changed = !Objects.equals(mapping.getBindingVersion(), binding.getBindingId())
                        || !Objects.equals(normalizeCategory(mapping.getDeviceCategory()), category)
                        || !Objects.equals(mapping.getBindingUpdatedAt(), binding.getBindTime())
                        || !Objects.equals(mapping.getPrincipalId(), principal.getPrincipalId());
                if (changed) {
                    mapping.setPrincipalId(principal.getPrincipalId());
                    mapping.syncBindingFact(binding.getBindingId(), binding.getBindTime());
                    mapping.setDeviceCategory(category);
                    mappingRepository.save(mapping);
                    outcome.synced++;
                } else {
                    outcome.unchanged++;
                }
            }
        }

        // 快照中已不存在的 ACTIVE 映射 → UNBOUND（被跳过的 SN 仍在 snapshotDeviceSns 内，不会误判）
        for (PrincipalAssetMapping mapping : current) {
            if (mapping.getState() != PrincipalAssetMapping.MappingState.ACTIVE) {
                continue;
            }
            if (!snapshotDeviceSns.contains(mapping.getDeviceSn())) {
                mapping.unbind();
                mappingRepository.save(mapping);
                outcome.unbound++;
            }
        }

        audit(eventId, vin, firstPrincipal, enrollable, outcome);
        return outcome;
    }

    /**
     * 写安全操作审计（一次事件一条汇总记录）
     */
    private void audit(String eventId, String vin, SecurityPrincipal principal,
                       List<VehiclePartBindingExResponse> enrollable, Outcome outcome) {
        String detail = "created=" + outcome.created + ",synced=" + outcome.synced
                + ",superseded=" + outcome.superseded + ",unbound=" + outcome.unbound
                + ",unchanged=" + outcome.unchanged + ",enrollable=" + enrollable.size();
        SecurityOperationAudit audit = SecurityOperationAudit.builder()
                .operationId(net.hwyz.iov.cloud.sec.viam.service.common.util.ViamUtils
                        .operationId("BFE", eventId, System.currentTimeMillis()))
                .principalId(principal == null ? null : principal.getPrincipalId())
                .hsmUid(null)
                .vin(vin)
                .deviceSn(principal == null ? null : null)
                .operation("BINDING_FACT_ENROLLMENT")
                .securityVersion(0L)
                .reason("EVENT_TRIGGERED")
                .detail(detail)
                .operatorId("SYSTEM")
                .callerType("EVENT")
                .occurredAt(java.time.Instant.now())
                .build();
        try {
            auditRepository.save(audit);
        } catch (Exception e) {
            log.warn("绑定事实登记审计写入失败（不影响收敛结果）: eventId={}, err={}", eventId, e.getMessage());
        }
    }

    private static String normalizeCategory(String value) {
        if (value == null) {
            return null;
        }
        String normalized = value.trim().toUpperCase(Locale.ROOT);
        return normalized.isEmpty() ? null : normalized;
    }

    /**
     * 收敛结果计数
     */
    @Getter
    public static class Outcome {
        private int created;
        private int synced;
        private int superseded;
        private int unbound;
        private int unchanged;
    }
}
