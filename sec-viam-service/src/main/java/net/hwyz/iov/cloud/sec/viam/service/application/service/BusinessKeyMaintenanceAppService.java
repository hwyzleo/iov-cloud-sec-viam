package net.hwyz.iov.cloud.sec.viam.service.application.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.DeviceBusinessKey;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.DeviceBusinessKeyRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * 业务密钥维护应用服务（SEC-VIAM-DSN-CR-001 / FR-VIAM-003 / D-VIAM-004）
 * <p>
 * 迁入 VMD 管理查询/轮换/吊销/清阻断职能；轮换不重派生已冻结材料、
 * 吊销不生成新版本、清阻断仅解除状态阻断。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class BusinessKeyMaintenanceAppService {

    private final DeviceBusinessKeyRepository businessKeyRepository;

    /**
     * 轮换：当前 ACTIVE → DEPRECATED（旧材料仅解密窗口内可用），
     * 新版本目录行由后续开通流程创建（不在此重派生）。
     */
    @Transactional(rollbackFor = Exception.class)
    public void rotate(String deviceSn, String businessDomain, String purpose, String operatorId) {
        DeviceBusinessKey active = businessKeyRepository.findActiveByContext(deviceSn, businessDomain, purpose)
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.BUSINESS_KEY_NOT_EXIST));
        active.deprecateForRotation(Instant.now().plus(7, ChronoUnit.DAYS));
        businessKeyRepository.save(active);
        log.info("业务密钥轮换降级: deviceSn={}, purpose={}, operatorId={}", deviceSn, purpose, operatorId);
    }

    /**
     * 吊销：ACTIVE/DEPRECATED → REVOKED（终态）。
     */
    @Transactional(rollbackFor = Exception.class)
    public void revoke(String deviceSn, String businessDomain, String purpose, String operatorId) {
        DeviceBusinessKey active = businessKeyRepository.findActiveByContext(deviceSn, businessDomain, purpose)
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.BUSINESS_KEY_NOT_EXIST));
        active.revoke();
        businessKeyRepository.save(active);
        log.info("业务密钥吊销: deviceSn={}, purpose={}, operatorId={}", deviceSn, purpose, operatorId);
    }

    /**
     * 清阻断：RECONCILE_REQUIRED/PENDING_RECOVERY → PENDING（解除状态阻断，不重派生）。
     */
    @Transactional(rollbackFor = Exception.class)
    public void clearBlocking(String deviceSn, String businessDomain, String purpose, String operatorId) {
        DeviceBusinessKey key = businessKeyRepository.findActiveByContext(deviceSn, businessDomain, purpose)
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.BUSINESS_KEY_NOT_EXIST));
        if (key.getKeyState() != DeviceBusinessKey.KeyState.RECONCILE_REQUIRED
                && key.getKeyState() != DeviceBusinessKey.KeyState.PENDING_RECOVERY
                && key.getKeyState() != DeviceBusinessKey.KeyState.FAILED) {
            throw new ViamServiceException(ViamErrorCode.BUSINESS_KEY_STATE_NOT_ALLOWED);
        }
        key.setKeyState(DeviceBusinessKey.KeyState.PENDING);
        businessKeyRepository.save(key);
        log.info("业务密钥清阻断: deviceSn={}, purpose={}, operatorId={}", deviceSn, purpose, operatorId);
    }
}
