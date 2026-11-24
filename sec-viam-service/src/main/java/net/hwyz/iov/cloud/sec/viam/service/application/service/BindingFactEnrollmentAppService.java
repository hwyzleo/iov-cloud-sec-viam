package net.hwyz.iov.cloud.sec.viam.service.application.service;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.edd.vmd.api.vo.response.VehiclePartBindingExResponse;
import net.hwyz.iov.cloud.sec.viam.service.adapter.kafka.BindingEnrollmentProperties;
import net.hwyz.iov.cloud.sec.viam.service.adapter.kafka.dto.VmdPartBindingChangedPayload;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.vmd.VmdBindingFactAdapter;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * 绑定事实自动登记编排（SEC-VIAM-DSN-CR-006 / D-VIAM-028～034）
 * <p>
 * 事件仅作触发信号：按事件 `vin` 回查 VMD active 绑定快照，白名单类别 + 芯片 UID 可用的条目进入事务收敛；
 * 芯片 UID 缺失/非法的条目单条跳过并计入 skipped，不阻塞同车其他设备；FEIGN 在事务外执行。
 * </p>
 *
 * @author hwyz_leo
 * @since 2026-11-24
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class BindingFactEnrollmentAppService {

    private final VmdBindingFactAdapter vmdBindingFactAdapter;
    private final BindingFactSnapshotApplier snapshotApplier;
    private final BindingEnrollmentProperties properties;

    /**
     * 处理绑定变更事件
     *
     * @param payload     事件载荷（仅取 vin/eventId 等触发信息）
     * @param sourceTopic 来源 topic（日志与审计）
     * @return 处理结果
     */
    public Result handle(VmdPartBindingChangedPayload payload, String sourceTopic) {
        String vin = payload.getVin() == null ? null : payload.getVin().trim();
        if (vin == null || vin.isEmpty()) {
            throw new ViamServiceException(ViamErrorCode.CERTIFICATE_VIN_NOT_EXIST, "绑定事件缺少VIN");
        }
        if (!properties.isEnabled()) {
            log.info("绑定事实自动登记已关闭，跳过: eventId={}, vin={}", payload.getEventId(), vin);
            return new Result(0, List.of(), 0, 0, 0, 0, 0);
        }

        // Feign 在事务外：快照即事实
        List<VehiclePartBindingExResponse> bindings = vmdBindingFactAdapter.listActiveBindingsByVin(vin);
        if (bindings == null) {
            bindings = List.of();
        }
        if (bindings.size() > properties.getMaxSnapshotBindings()) {
            throw new ViamServiceException(ViamErrorCode.PRINCIPAL_UID_UNAVAILABLE,
                    "绑定快照超上限: size=" + bindings.size());
        }

        Set<String> snapshotDeviceSns = new LinkedHashSet<>();
        List<VehiclePartBindingExResponse> enrollable = new ArrayList<>();
        List<String> skipped = new ArrayList<>();
        for (VehiclePartBindingExResponse binding : bindings) {
            if (binding.getSn() != null) {
                snapshotDeviceSns.add(binding.getSn());
            }
            if (!isAllowedCategory(binding.getDeviceCategory())) {
                continue;
            }
            if (isBlank(binding.getChipUid())) {
                // 单条隔离：不建主体、不建映射，但事件整体置隔离以便重放
                skipped.add(binding.getSn());
                continue;
            }
            enrollable.add(binding);
        }

        BindingFactSnapshotApplier.Outcome outcome = snapshotApplier.apply(
                vin, payload.getEventId(), enrollable, snapshotDeviceSns, properties.getEnrollSourceSystem());

        log.info("BINDING-CHANGED | eventId={}, vin={}, changeType={}, topic={}, bindings={}, enrollable={}, "
                        + "skipped={}, created={}, synced={}, superseded={}, unbound={}",
                payload.getEventId(), vin, payload.getChangeType(), sourceTopic, bindings.size(),
                enrollable.size(), skipped, outcome.getCreated(), outcome.getSynced(),
                outcome.getSuperseded(), outcome.getUnbound());

        return new Result(bindings.size(), skipped, outcome.getCreated(), outcome.getSynced(),
                outcome.getSuperseded(), outcome.getUnbound(), outcome.getUnchanged());
    }

    private boolean isAllowedCategory(String deviceCategory) {
        String normalized = normalize(deviceCategory);
        if (normalized == null) {
            return false;
        }
        List<String> allowed = properties.getAllowedCategories();
        if (allowed == null || allowed.isEmpty()) {
            return false;
        }
        for (String category : allowed) {
            if (normalized.equals(normalize(category))) {
                return true;
            }
        }
        return false;
    }

    private static String normalize(String value) {
        if (value == null) {
            return null;
        }
        String normalized = value.trim().toUpperCase(Locale.ROOT);
        return normalized.isEmpty() ? null : normalized;
    }

    private static boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }

    /**
     * 处理结果
     */
    @Getter
    public static class Result {

        /** 快照绑定数 */
        private final int snapshotSize;

        /** 因芯片 UID 缺失被跳过的 SN */
        private final List<String> skippedDeviceSns;

        /** 新建映射数 */
        private final int created;

        /** 投影同步数 */
        private final int synced;

        /** 换件退出 ACTIVE 数 */
        private final int superseded;

        /** 解绑（UNBOUND）数 */
        private final int unbound;

        /** 无变化数 */
        private final int unchanged;

        public Result(int snapshotSize, List<String> skippedDeviceSns, int created, int synced,
                      int superseded, int unbound, int unchanged) {
            this.snapshotSize = snapshotSize;
            this.skippedDeviceSns = skippedDeviceSns;
            this.created = created;
            this.synced = synced;
            this.superseded = superseded;
            this.unbound = unbound;
            this.unchanged = unchanged;
        }

        /** 是否存在被跳过的条目（事件需隔离待重放） */
        public boolean hasSkipped() {
            return skippedDeviceSns != null && !skippedDeviceSns.isEmpty();
        }
    }
}
