package net.hwyz.iov.cloud.sec.viam.service.application.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;
import net.hwyz.iov.cloud.framework.common.bean.PageResult;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateApplyResultVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateApplyVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateCompensateVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateConfirmInstalledVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateDetailVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateListItemVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateMaterialVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateOperationResultVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateOperationVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateReconcileVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateReissueVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateStatusVo;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import net.hwyz.iov.cloud.sec.viam.service.common.util.ViamUtils;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.CertificateOperation;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.CredentialEnrollment;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.PrincipalAssetMapping;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SecurityPrincipal;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.query.CertificatePage;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.query.CertificateQuery;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.CertificateOperationRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.CredentialEnrollmentRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.PrincipalAssetMappingRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.SecurityPrincipalRepository;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.pki.CertEnrollmentAdapter;
import net.hwyz.iov.cloud.framework.security.crypto.model.IssuedCertificate;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * 设备证书生命周期应用服务（SEC-VIAM-DSN-CR-001 / FR-VIAM-002 / D-VIAM-004）
 * <p>
 * 迁入 VMD CertificateProvisioningAppService 的证书申请/安装/补偿语义与目录职能；
 * 保留 Profile/CSR 意图校验、签发后复验、结果未知恢复。PKI/CA 仍负责实际签发及吊销权威。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CertificateProvisioningAppService {

    private final CredentialEnrollmentRepository enrollmentRepository;
    private final SecurityPrincipalRepository principalRepository;
    private final PrincipalAssetMappingRepository assetMappingRepository;
    private final CertificateOperationRepository certificateOperationRepository;
    private final CertificateOperationRecorder operationRecorder;
    private final CertEnrollmentAdapter certEnrollmentAdapter;

    /**
     * 申请设备证书（幂等占位 + 同步签发；不跨慢网络 I/O 持事务）。
     */
    public CertificateApplyResultVo apply(CertificateApplyVo cmd) {
        log.info("申请设备证书: requestId={}, vin={}, deviceSn={}, profile={}",
                cmd.getRequestId(), cmd.getVin(), cmd.getDeviceSn(), cmd.getCertificateProfile());

        // 1. 幂等检查（request_id 占位）
        CredentialEnrollment existing = enrollmentRepository.findByRequestId(cmd.getRequestId()).orElse(null);
        if (existing != null) {
            return buildApplyResult(existing, null);
        }

        // 2. 主体校验（受信身份）
        SecurityPrincipal principal = resolvePrincipal(cmd);
        if (principal.getState() != SecurityPrincipal.PrincipalState.ACTIVE) {
            throw new ViamServiceException(ViamErrorCode.CERTIFICATE_VIN_NOT_EXIST);
        }

        // 3. 同身份同公钥幂等复用
        CredentialEnrollment reused = enrollmentRepository.findByVinAndUidAndSpkiAndProfile(
                cmd.getVin(), principal.getHsmUid(), null, cmd.getCertificateProfile()).orElse(null);
        if (reused != null && reused.isReusableStatus()) {
            return buildApplyResult(reused, null);
        }

        // 4. 建占位行（REQUESTED）
        CredentialEnrollment enrollment = CredentialEnrollment.builder()
                .requestId(cmd.getRequestId())
                .vin(cmd.getVin())
                .deviceCategory(cmd.getDeviceCategory())
                .deviceSn(cmd.getDeviceSn())
                .hsmUid(principal.getHsmUid())
                .certificateProfile(cmd.getCertificateProfile())
                .certStatus(CredentialEnrollment.CertificateState.REQUESTED)
                .sourceSystem(cmd.getSourceSystem())
                .originalRequestId(cmd.getOriginalRequestId())
                .compensationReason(cmd.getCompensationReason())
                .ticketNo(cmd.getTicketNo())
                .facilityNo(cmd.getFacilityNo())
                .lineCode(cmd.getLineCode())
                .build();
        try {
            enrollmentRepository.insert(enrollment);
        } catch (DuplicateKeyException e) {
            CredentialEnrollment raced = enrollmentRepository.findByRequestId(cmd.getRequestId()).orElse(null);
            if (raced != null) {
                return buildApplyResult(raced, null);
            }
            throw e;
        }

        // 5. 调用 FW-SEC 证书注册模板申请（事务外；结果未知转 PENDING_RECONCILE）
        try {
            certEnrollmentAdapter.apply(enrollment, cmd.getCsrDerBase64());
        } catch (net.hwyz.iov.cloud.framework.security.crypto.exception.PkiOutcomeUnknownException e) {
            log.warn("证书申请结果未知，转待对账: requestId={}", cmd.getRequestId());
            enrollment.markPendingReconcile(e.getMessage());
            enrollmentRepository.update(enrollment);
        } catch (Exception e) {
            log.error("证书申请失败: requestId={}", cmd.getRequestId(), e);
            enrollment.markFailed(e.getMessage());
            enrollmentRepository.update(enrollment);
            throw e;
        }

        return buildApplyResult(enrollment, null);
    }

    /**
     * 人工补偿/对账（MPT）：PENDING_RECONCILE/FAILED 状态经 CSR 重发或 PKI 对账推进。
     * <p>
     * 结果未知禁止自动重签，转 PENDING_RECONCILE；终态不得回退。
     * </p>
     */
    @Transactional(rollbackFor = Exception.class)
    public CertificateApplyResultVo reconcile(String requestId, String csrDerBase64) {
        CredentialEnrollment enrollment = enrollmentRepository.findByRequestId(requestId)
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.CERTIFICATE_REQUEST_NOT_EXIST));
        if (enrollment.getCertStatus() != CredentialEnrollment.CertificateState.PENDING_RECONCILE
                && enrollment.getCertStatus() != CredentialEnrollment.CertificateState.FAILED
                && enrollment.getCertStatus() != CredentialEnrollment.CertificateState.ISSUING) {
            throw new ViamServiceException(ViamErrorCode.CERTIFICATE_COMPENSATION_NOT_ALLOWED);
        }
        if (enrollment.getCertStatus() == CredentialEnrollment.CertificateState.FAILED && csrDerBase64 != null) {
            // 失败重试：按原 requestId/idempotencyKey 重新 apply
            try {
                certEnrollmentAdapter.apply(enrollment, csrDerBase64);
                enrollmentRepository.update(enrollment);
            } catch (net.hwyz.iov.cloud.framework.security.crypto.exception.PkiOutcomeUnknownException e) {
                enrollment.markPendingReconcile(e.getMessage());
                enrollmentRepository.update(enrollment);
            } catch (Exception e) {
                enrollment.markFailed(e.getMessage());
                enrollmentRepository.update(enrollment);
                throw e;
            }
        } else if (enrollment.getPkiRequestId() != null) {
            // 有 pki_request_id：getStatus/getCertificate 对账推进
            try {
                certEnrollmentAdapter.reconcile(enrollment);
                enrollmentRepository.update(enrollment);
            } catch (Exception e) {
                log.warn("对账查询PKI状态失败，转待对账: requestId={}", requestId, e);
                enrollment.markPendingReconcile(e.getMessage());
                enrollmentRepository.update(enrollment);
            }
        } else {
            throw new ViamServiceException(ViamErrorCode.CERTIFICATE_MATERIAL_UNAVAILABLE,
                    "无 pki_request_id 且无 CSR，无法自动推进，请人工补申请");
        }
        return buildApplyResult(enrollment, null);
    }

    /**
     * 查询证书申请状态（ISSUING 时尝试对账推进）。
     */
    public CertificateStatusVo status(String requestId) {
        CredentialEnrollment enrollment = enrollmentRepository.findByRequestId(requestId)
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.CERTIFICATE_REQUEST_NOT_EXIST));
        if (enrollment.getCertStatus() == CredentialEnrollment.CertificateState.ISSUING
                && enrollment.getPkiRequestId() != null) {
            try {
                certEnrollmentAdapter.reconcile(enrollment);
            } catch (Exception e) {
                log.warn("状态查询对账失败: requestId={}", requestId, e);
            }
        }
        return buildStatusVo(enrollment);
    }

    /**
     * 确认证书安装（事务内：作废同设备同 Profile 既有 ACTIVE 后激活）。
     */
    @Transactional(rollbackFor = Exception.class)
    public void confirmInstalled(CertificateConfirmInstalledVo cmd) {
        confirmInstalled(cmd, null, null, null);
    }

    /**
     * 确认证书安装（管理面带操作人/审计；SEC-VIAM-DSN-CR-002 / D-VIAM-013 / D-VIAM-014）。
     * <p>
     * 操作人一律由适配层从 EIAM 会话解析后传入，忽略请求体自报值。
     * </p>
     */
    @Transactional(rollbackFor = Exception.class)
    public CertificateOperationResultVo confirmInstalled(CertificateConfirmInstalledVo cmd,
                                                         String operatorId,
                                                         String sourceIp,
                                                         String userAgent) {
        CredentialEnrollment enrollment = enrollmentRepository.findByRequestId(cmd.getRequestId())
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.CERTIFICATE_REQUEST_NOT_EXIST));
        String beforeStatus = enrollment.getCertStatus().name();
        if (enrollment.getCertStatus() != CredentialEnrollment.CertificateState.ISSUED_NOT_CONFIRMED
                && enrollment.getCertStatus() != CredentialEnrollment.CertificateState.INSTALL_FAILED) {
            throw new ViamServiceException(ViamErrorCode.CERTIFICATE_STATUS_NOT_ALLOWED);
        }
        // 可选一致性校验：提供即必须与记录一致（702211），避免补录错对象
        if (notBlank(cmd.getCertSn()) && !ViamUtils.canonicalCertSn(cmd.getCertSn())
                .equalsIgnoreCase(ViamUtils.canonicalCertSn(enrollment.getCertSn()))) {
            throw new ViamServiceException(ViamErrorCode.CERTIFICATE_INSTALL_CONFIRM_MISMATCH);
        }
        if (notBlank(cmd.getDeviceSn()) && !cmd.getDeviceSn().equals(enrollment.getDeviceSn())) {
            throw new ViamServiceException(ViamErrorCode.CERTIFICATE_INSTALL_CONFIRM_MISMATCH);
        }
        if (notBlank(cmd.getVin()) && !cmd.getVin().equals(enrollment.getVin())) {
            throw new ViamServiceException(ViamErrorCode.CERTIFICATE_INSTALL_CONFIRM_MISMATCH);
        }
        if ("SUCCESS".equals(cmd.getResult())) {
            enrollmentRepository.supersedeActiveByDeviceSnAndProfile(
                    enrollment.getDeviceSn(), enrollment.getCertificateProfile(), enrollment.getRequestId());
            enrollment.confirmInstalled();
        } else {
            enrollment.confirmInstallFailed(cmd.getFailReason());
        }
        String effectiveOperator = notBlank(operatorId) ? operatorId : cmd.getOperatorId();
        enrollment.setLastOperator(effectiveOperator);
        enrollment.setLastOperationAt(Instant.now());
        enrollmentRepository.update(enrollment);

        CertificateOperation operation = operationRecorder.record(
                CertificateOperation.Action.CONFIRM_INSTALLED, enrollment.getRequestId(),
                effectiveOperator, null, cmd.getReason(), cmd.getTicketNo(),
                enrollment.getOriginalRequestId(), beforeStatus, enrollment.getCertStatus().name(),
                CertificateOperation.Result.SUCCESS, null, null, sourceIp, userAgent);
        return buildOperationResult(operation, enrollment);
    }

    /**
     * 按证书序列号查询。
     */
    public CertificateStatusVo getByCertSn(String certSn) {
        CredentialEnrollment enrollment = enrollmentRepository.findByCertSn(ViamUtils.canonicalCertSn(certSn))
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.CERTIFICATE_REQUEST_NOT_EXIST));
        return buildStatusVo(enrollment);
    }

    /**
     * 查询更新时间大于指定时间的证书列表（对账）。
     */
    public List<CertificateStatusVo> listChanged(Instant updatedAfter, int limit) {
        return enrollmentRepository.listUpdatedAfter(updatedAfter, limit).stream()
                .map(this::buildStatusVo)
                .toList();
    }

    // ================= 管理面（MPT）能力：SEC-VIAM-DSN-CR-002 =================

    /**
     * 管理面多条件分页查询（D-VIAM-011 / D-VIAM-012）。
     * <p>
     * 分页由适配层的 PageHelper 上下文控制；列表不返回 CSR 全文与证书本体。
     * </p>
     */
    public PageResult<CertificateListItemVo> search(CertificateQuery query) {
        CertificatePage page = enrollmentRepository.page(query);
        PageResult<CertificateListItemVo> result = new PageResult<>();
        result.setItems(page.items().stream().map(this::toListItem).collect(Collectors.toList()));
        result.setTotal(page.total());
        return result;
    }

    /**
     * 管理面详情 + 脱敏操作审计时间线（D-VIAM-013）。
     */
    public CertificateDetailVo detail(String requestId) {
        CredentialEnrollment enrollment = enrollmentRepository.findByRequestId(requestId)
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.CERTIFICATE_REQUEST_NOT_EXIST));
        CertificateDetailVo vo = CertificateDetailVo.builder()
                .requestId(enrollment.getRequestId())
                .originalRequestId(enrollment.getOriginalRequestId())
                .pkiRequestId(enrollment.getPkiRequestId())
                .vin(enrollment.getVin())
                .deviceCategory(enrollment.getDeviceCategory())
                .deviceSn(enrollment.getDeviceSn())
                .certificateProfile(enrollment.getCertificateProfile())
                .csrFingerprint(enrollment.getCsrFingerprint())
                .subject(enrollment.getSubject())
                .issuer(enrollment.getIssuer())
                .certSn(enrollment.getCertSn())
                .status(enrollment.getCertStatus() == null ? null : enrollment.getCertStatus().name())
                .sourceSystem(enrollment.getSourceSystem())
                .certificateFingerprint(enrollment.getCertificateFingerprint())
                .notBefore(enrollment.getNotBefore())
                .notAfter(enrollment.getNotAfter())
                .issuedAt(enrollment.getIssuedAt())
                .confirmedAt(enrollment.getConfirmedAt())
                .compensationReason(enrollment.getCompensationReason())
                .ticketNo(enrollment.getTicketNo())
                .lastOperator(enrollment.getLastOperator())
                .lastOperationAt(enrollment.getLastOperationAt())
                .failReason(enrollment.getFailReason())
                .build();
        vo.setOperations(certificateOperationRepository.listByRequestId(requestId).stream()
                .map(this::toOperationVo)
                .collect(Collectors.toList()));
        return vo;
    }

    /**
     * 人工补申请（MES 请求未达场景；D-VIAM-014）。
     * <p>
     * 后台不生成设备密钥或 CSR；主体由受信资产映射反查，不采信客户端自报 UID。
     * </p>
     */
    @Transactional(rollbackFor = Exception.class)
    public CertificateOperationResultVo compensate(CertificateCompensateVo cmd, String operatorId,
                                                   String operationName, String sourceIp, String userAgent) {
        String requestId = notBlank(cmd.getRequestId()) ? cmd.getRequestId()
                : "MPT-CERT-" + UUID.randomUUID();
        boolean existedBefore = enrollmentRepository.findByRequestId(requestId).isPresent();

        // 受信主体解析：设备SN → ACTIVE 资产映射 → 安全主体（不得仅信自报 UID）
        SecurityPrincipal principal = resolvePrincipalByDeviceSn(cmd.getDeviceSn());

        CertificateApplyVo applyCmd = CertificateApplyVo.builder()
                .requestId(requestId)
                .vin(cmd.getVin())
                .deviceCategory(cmd.getDeviceCategory())
                .deviceSn(cmd.getDeviceSn())
                .ecuUid(principal.getHsmUid())
                .certificateProfile(cmd.getCertificateProfile())
                .csrDerBase64(cmd.getCsrDerBase64())
                .sourceSystem("MPT_COMPENSATION")
                .originalRequestId(cmd.getOriginalRequestId())
                .compensationReason(cmd.getReason())
                .ticketNo(cmd.getTicketNo())
                .operatorId(operatorId)
                .facilityNo(cmd.getFacilityNo())
                .lineCode(cmd.getLineCode())
                .build();

        CertificateApplyResultVo applied = apply(applyCmd);
        CredentialEnrollment enrollment = enrollmentRepository.findByRequestId(requestId)
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.CERTIFICATE_REQUEST_NOT_EXIST));

        CertificateOperation operation = operationRecorder.record(
                CertificateOperation.Action.COMPENSATE, requestId, operatorId, operationName,
                cmd.getReason(), cmd.getTicketNo(), cmd.getOriginalRequestId(),
                existedBefore ? enrollment.getCertStatus().name() : null,
                enrollment.getCertStatus().name(),
                existedBefore ? CertificateOperation.Result.IDEMPOTENT_HIT : CertificateOperation.Result.SUCCESS,
                applied.getFailReason(), cmd.getCsrDerBase64(), sourceIp, userAgent);
        return buildOperationResult(operation, enrollment);
    }

    /**
     * 管理面对账（带原因/工单与审计；D-VIAM-013）。
     */
    @Transactional(rollbackFor = Exception.class)
    public CertificateOperationResultVo reconcileForMpt(String requestId, CertificateReconcileVo cmd,
                                                        String operatorId, String sourceIp, String userAgent) {
        CredentialEnrollment before = enrollmentRepository.findByRequestId(requestId)
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.CERTIFICATE_REQUEST_NOT_EXIST));
        String beforeStatus = before.getCertStatus().name();
        CertificateApplyResultVo applied = reconcile(requestId, cmd == null ? null : cmd.getCsrDerBase64());
        CredentialEnrollment after = enrollmentRepository.findByRequestId(requestId)
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.CERTIFICATE_REQUEST_NOT_EXIST));

        CertificateOperation operation = operationRecorder.record(
                CertificateOperation.Action.RECONCILE, requestId, operatorId, null,
                cmd == null ? null : cmd.getReason(), cmd == null ? null : cmd.getTicketNo(),
                after.getOriginalRequestId(), beforeStatus, applied.getStatus(),
                CertificateOperation.Result.SUCCESS, applied.getFailReason(),
                cmd == null ? null : cmd.getCsrDerBase64(), sourceIp, userAgent);
        return buildOperationResult(operation, after);
    }

    /**
     * 获取已签发证书本体（只读；D-VIAM-015）。
     * <p>
     * 不落库、不缓存；PKI 已无材料时明确失败（702221）；
     * 审计写入失败则整体失败，不返回证书材料（fail-closed）。
     * </p>
     */
    @Transactional(rollbackFor = Exception.class)
    public CertificateMaterialVo queryCertificateMaterial(String requestId, String operatorId,
                                                           String sourceIp, String userAgent) {
        CredentialEnrollment enrollment = enrollmentRepository.findByRequestId(requestId)
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.CERTIFICATE_REQUEST_NOT_EXIST));
        CredentialEnrollment.CertificateState state = enrollment.getCertStatus();
        if (state != CredentialEnrollment.CertificateState.ISSUED_NOT_CONFIRMED
                && state != CredentialEnrollment.CertificateState.ACTIVE
                && state != CredentialEnrollment.CertificateState.EXPIRED) {
            throw new ViamServiceException(ViamErrorCode.CERTIFICATE_STATUS_NOT_ALLOWED);
        }
        IssuedCertificate issued;
        try {
            issued = certEnrollmentAdapter.getCertificate(enrollment.getPkiRequestId());
        } catch (Exception e) {
            log.warn("证书材料重取失败: requestId={}, cause={}", requestId, e.getMessage());
            throw new ViamServiceException(ViamErrorCode.CERTIFICATE_MATERIAL_UNAVAILABLE);
        }
        if (issued == null) {
            throw new ViamServiceException(ViamErrorCode.CERTIFICATE_MATERIAL_NOT_RETRIEVABLE);
        }
        // 先落审计再返回材料：审计不可用时不外泄敏感材料
        operationRecorder.record(
                CertificateOperation.Action.QUERY_CERTIFICATE, requestId, operatorId, null,
                null, enrollment.getTicketNo(), enrollment.getOriginalRequestId(),
                state.name(), state.name(), CertificateOperation.Result.SUCCESS,
                null, null, sourceIp, userAgent);

        return CertificateMaterialVo.builder()
                .requestId(requestId)
                .certSn(enrollment.getCertSn())
                .certificateFingerprint(enrollment.getCertificateFingerprint())
                .certificateDerBase64(Base64.getEncoder().encodeToString(issued.leafCertificate()))
                .chainDerBase64(issued.certificateChain().stream()
                        .map(der -> Base64.getEncoder().encodeToString(der))
                        .toArray(String[]::new))
                .build();
    }

    /**
     * 重新签发/续期（D-VIAM-016）。
     * <p>
     * 新记录独立 requestId，旧记录进入 SUPERSEDED 终态；禁止原地覆盖旧行证书字段。
     * </p>
     */
    @Transactional(rollbackFor = Exception.class)
    public CertificateOperationResultVo reissue(String oldRequestId, CertificateReissueVo cmd,
                                                String operatorId, String sourceIp, String userAgent) {
        CredentialEnrollment old = enrollmentRepository.findByRequestId(oldRequestId)
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.CERTIFICATE_REQUEST_NOT_EXIST));
        String beforeStatus = old.getCertStatus().name();
        try {
            old.supersedeForReissue();
        } catch (IllegalStateException e) {
            throw new ViamServiceException(ViamErrorCode.CERTIFICATE_STATUS_NOT_ALLOWED);
        }

        String newRequestId = notBlank(cmd.getRequestId()) ? cmd.getRequestId()
                : "MPT-REISSUE-" + UUID.randomUUID();
        SecurityPrincipal principal = principalRepository.findByHsmUid(old.getHsmUid())
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.PRINCIPAL_UID_UNAVAILABLE));

        CertificateApplyVo applyCmd = CertificateApplyVo.builder()
                .requestId(newRequestId)
                .vin(old.getVin())
                .deviceCategory(old.getDeviceCategory())
                .deviceSn(old.getDeviceSn())
                .ecuUid(principal.getHsmUid())
                .certificateProfile(old.getCertificateProfile())
                .csrDerBase64(cmd.getCsrDerBase64())
                .sourceSystem("MPT_COMPENSATION")
                .originalRequestId(old.getOriginalRequestId())
                .compensationReason(cmd.getReason())
                .ticketNo(cmd.getTicketNo())
                .operatorId(operatorId)
                .facilityNo(old.getFacilityNo())
                .lineCode(old.getLineCode())
                .build();

        // 先作废旧证，再以新 requestId 走同一套申请语义（新行独立，不复用旧行）
        enrollmentRepository.update(old);
        CertificateApplyResultVo applied = apply(applyCmd);
        CredentialEnrollment created = enrollmentRepository.findByRequestId(newRequestId)
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.CERTIFICATE_REQUEST_NOT_EXIST));

        CertificateOperation operation = operationRecorder.record(
                CertificateOperation.Action.REISSUE, newRequestId, operatorId, null,
                cmd.getReason(), cmd.getTicketNo(), old.getOriginalRequestId(),
                beforeStatus, created.getCertStatus().name(),
                CertificateOperation.Result.SUCCESS, applied.getFailReason(),
                cmd.getCsrDerBase64(), sourceIp, userAgent);
        return buildOperationResult(operation, created);
    }

    /**
     * 按设备SN解析受信安全主体（资产映射 → 主体；状态必须 ACTIVE）。
     */
    private SecurityPrincipal resolvePrincipalByDeviceSn(String deviceSn) {
        PrincipalAssetMapping mapping = assetMappingRepository.findActiveByDeviceSn(deviceSn)
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.CERTIFICATE_DEVICE_NOT_BOUND));
        SecurityPrincipal principal = principalRepository.findByPrincipalId(mapping.getPrincipalId())
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.PRINCIPAL_UID_UNAVAILABLE));
        if (principal.getState() != SecurityPrincipal.PrincipalState.ACTIVE) {
            throw new ViamServiceException(ViamErrorCode.PRINCIPAL_UID_UNAVAILABLE);
        }
        return principal;
    }

    private CertificateListItemVo toListItem(CredentialEnrollment e) {
        return CertificateListItemVo.builder()
                .requestId(e.getRequestId())
                .originalRequestId(e.getOriginalRequestId())
                .vin(e.getVin())
                .deviceCategory(e.getDeviceCategory())
                .deviceSn(e.getDeviceSn())
                .certificateProfile(e.getCertificateProfile())
                .certSn(e.getCertSn())
                .status(e.getCertStatus() == null ? null : e.getCertStatus().name())
                .sourceSystem(e.getSourceSystem())
                .certificateFingerprint(e.getCertificateFingerprint())
                .notBefore(e.getNotBefore())
                .notAfter(e.getNotAfter())
                .issuedAt(e.getIssuedAt())
                .confirmedAt(e.getConfirmedAt())
                .lastOperator(e.getLastOperator())
                .lastOperationAt(e.getLastOperationAt())
                .failReason(e.getFailReason())
                .build();
    }

    private CertificateOperationVo toOperationVo(CertificateOperation op) {
        return CertificateOperationVo.builder()
                .operationId(op.getOperationId())
                .action(op.getAction() == null ? null : op.getAction().name())
                .operatorId(op.getOperatorId())
                .operatorName(op.getOperatorName())
                .reason(op.getReason())
                .ticketNo(op.getTicketNo())
                .beforeStatus(op.getBeforeStatus())
                .afterStatus(op.getAfterStatus())
                .result(op.getResult() == null ? null : op.getResult().name())
                .errorCode(op.getErrorCode())
                .occurredAt(op.getOccurredAt())
                .build();
    }

    private CertificateOperationResultVo buildOperationResult(CertificateOperation operation,
                                                              CredentialEnrollment enrollment) {
        return CertificateOperationResultVo.builder()
                .operationId(operation.getOperationId())
                .requestId(enrollment.getRequestId())
                .action(operation.getAction() == null ? null : operation.getAction().name())
                .status(enrollment.getCertStatus() == null ? null : enrollment.getCertStatus().name())
                .certSn(enrollment.getCertSn())
                .pkiRequestId(enrollment.getPkiRequestId())
                .issuer(enrollment.getIssuer())
                .fingerprint(enrollment.getCertificateFingerprint())
                .notBefore(enrollment.getNotBefore())
                .notAfter(enrollment.getNotAfter())
                .failReason(enrollment.getFailReason())
                .result(operation.getResult() == null ? null : operation.getResult().name())
                .occurredAt(operation.getOccurredAt())
                .build();
    }

    private static boolean notBlank(String value) {
        return value != null && !value.isBlank();
    }

    private SecurityPrincipal resolvePrincipal(CertificateApplyVo cmd) {
        // 受信主体登记（VMD事实/迁移/入站）为主；本地无登记时经受信入站登记建立
        SecurityPrincipal principal = principalRepository.findByHsmUid(ViamUtils.normalizeUid(cmd.getEcuUid()))
                .orElse(null);
        if (principal == null) {
            throw new ViamServiceException(ViamErrorCode.PRINCIPAL_UID_UNAVAILABLE);
        }
        return principal;
    }

    private CertificateApplyResultVo buildApplyResult(CredentialEnrollment e, Object unused) {
        return CertificateApplyResultVo.builder()
                .requestId(e.getRequestId())
                .status(e.getCertStatus().name())
                .certSn(e.getCertSn())
                .pkiRequestId(e.getPkiRequestId())
                .issuer(e.getIssuer())
                .fingerprint(e.getCertificateFingerprint())
                .notBefore(e.getNotBefore() == null ? null : e.getNotBefore().toString())
                .notAfter(e.getNotAfter() == null ? null : e.getNotAfter().toString())
                .failReason(e.getFailReason())
                .build();
    }

    private CertificateStatusVo buildStatusVo(CredentialEnrollment e) {
        return CertificateStatusVo.builder()
                .requestId(e.getRequestId())
                .status(e.getCertStatus().name())
                .certSn(e.getCertSn())
                .certificateFingerprint(e.getCertificateFingerprint())
                .issuer(e.getIssuer())
                .notBefore(e.getNotBefore())
                .notAfter(e.getNotAfter())
                .issuedAt(e.getIssuedAt())
                .confirmedAt(e.getConfirmedAt())
                .failReason(e.getFailReason())
                .build();
    }
}
