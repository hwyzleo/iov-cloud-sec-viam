package net.hwyz.iov.cloud.sec.viam.service.application.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;
import net.hwyz.iov.cloud.sec.viam.api.vo.ProvisioningBatchVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.ProvisioningDiagnosisVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.ProvisioningItemVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.ProvisioningLeaseVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.ProvisioningResolveVo;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.CredentialEnrollment;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.DeviceBusinessKey;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.KeyProvisioningLease;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.ProvisioningBatch;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.ProvisioningItem;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.CredentialEnrollmentRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.DeviceBusinessKeyRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.KeyProvisioningLeaseRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.ProvisioningBatchRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

/**
 * 业务密钥治理只读查询应用服务（SEC-VIAM-DSN-CR-002 / FR-VIAM-003 / D-VIAM-017）
 * <p>
 * 运维视角只读：不复用设备态 {@code status(context,...)}，不返回密钥材料、响应密文、
 * 信封字节与 digest 原始字节；桥接多命中时显式返回候选集，不静默择一。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class BusinessKeyGovernanceQueryAppService {

    /** 候选批次返回上限（防止无界查询） */
    private static final int CANDIDATE_LIMIT = 20;

    private final ProvisioningBatchRepository batchRepository;
    private final DeviceBusinessKeyRepository businessKeyRepository;
    private final KeyProvisioningLeaseRepository leaseRepository;
    private final CredentialEnrollmentRepository enrollmentRepository;

    /**
     * 按批次 requestId 查询治理视图（批次 + 明细 + 目录状态 + 最近租约 + 阻塞判定）。
     */
    @Transactional(readOnly = true)
    public ProvisioningBatchVo batch(String requestId) {
        ProvisioningBatch batch = batchRepository.findByRequestId(requestId)
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.KEYPROV_PROVISIONING_NOT_FOUND));
        List<ProvisioningItemVo> items = buildItems(batch);
        ProvisioningLeaseVo lease = buildLease(batch);
        Blocking blocking = evaluateBlocking(batch, items);

        return ProvisioningBatchVo.builder()
                .requestId(batch.getRequestId())
                .deviceSn(batch.getDeviceSn())
                .businessDomain(batch.getBusinessDomain())
                .status(batch.getStatus() == null ? null : batch.getStatus().name())
                .failReason(batch.getFailReason())
                .lifecycleProfile(batch.getLifecycleProfile())
                .firstIssuedAt(batch.getFirstIssuedAt())
                .ackDeadlineAt(batch.getAckDeadlineAt())
                .leaseSeq(batch.getLeaseSeq())
                .terminalReason(batch.getTerminalReason())
                .terminalAt(batch.getTerminalAt())
                .startedAt(batch.getStartedAt())
                .acknowledgedAt(batch.getAcknowledgedAt())
                .completedAt(batch.getCompletedAt())
                .modifyTime(batch.getModifyTime())
                .rowVersion(batch.getRowVersion())
                .blockingLevel(blocking.level())
                .blockingReason(blocking.reason())
                .items(items)
                .lease(lease)
                .build();
    }

    /**
     * 证书申请 requestId → 开通批次 requestId 只读桥接（D-VIAM-017）。
     * <p>
     * 证书申请与开通批次是两套标识：先由证书申请记录解析 deviceSn/vin，
     * 再按设备+业务域列出候选批次；未终结批次优先，多命中不静默择一。
     * </p>
     */
    @Transactional(readOnly = true)
    public ProvisioningResolveVo resolveByCertificateRequest(String certificateRequestId,
                                                             String businessDomain,
                                                             boolean includeTerminal) {
        CredentialEnrollment enrollment = enrollmentRepository.findByRequestId(certificateRequestId)
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.CERTIFICATE_REQUEST_NOT_EXIST));
        String domain = (businessDomain == null || businessDomain.isBlank())
                ? "V2C_COMM" : businessDomain.trim();

        List<ProvisioningBatch> batches = batchRepository.listByDeviceSnAndDomain(
                enrollment.getDeviceSn(), domain, includeTerminal, CANDIDATE_LIMIT);

        List<ProvisioningResolveVo.Candidate> candidates = batches.stream()
                .sorted(Comparator.comparing(ProvisioningBatch::getStartedAt,
                        Comparator.nullsLast(Comparator.reverseOrder())))
                .map(b -> ProvisioningResolveVo.Candidate.builder()
                        .requestId(b.getRequestId())
                        .status(b.getStatus() == null ? null : b.getStatus().name())
                        .open(isOpen(b))
                        .startedAt(b.getStartedAt())
                        .completedAt(b.getCompletedAt())
                        .build())
                .toList();

        String selected = null;
        String resolution;
        List<ProvisioningResolveVo.Candidate> openCandidates = candidates.stream()
                .filter(c -> Boolean.TRUE.equals(c.getOpen())).toList();
        if (openCandidates.size() == 1) {
            selected = openCandidates.get(0).getRequestId();
            resolution = "UNIQUE";
        } else if (openCandidates.size() > 1) {
            resolution = "MULTIPLE";
        } else if (candidates.size() == 1) {
            selected = candidates.get(0).getRequestId();
            resolution = "UNIQUE";
        } else if (candidates.isEmpty()) {
            resolution = "NONE";
        } else {
            resolution = "MULTIPLE";
        }

        return ProvisioningResolveVo.builder()
                .certificateRequestId(certificateRequestId)
                .deviceSn(enrollment.getDeviceSn())
                .vin(enrollment.getVin())
                .businessDomain(domain)
                .candidates(candidates)
                .selected(selected)
                .resolution(resolution)
                .build();
    }

    /**
     * 阻塞诊断（只读；D-VIAM-018）：标注阻塞层级、证据与可清理性判断。
     */
    @Transactional(readOnly = true)
    public ProvisioningDiagnosisVo diagnosis(String requestId) {
        ProvisioningBatch batch = batchRepository.findByRequestId(requestId)
                .orElseThrow(() -> new ViamServiceException(ViamErrorCode.KEYPROV_PROVISIONING_NOT_FOUND));
        List<ProvisioningItemVo> items = buildItems(batch);
        ProvisioningLeaseVo lease = buildLease(batch);
        Blocking blocking = evaluateBlocking(batch, items);

        List<String> evidence = new ArrayList<>();
        evidence.add("批次状态=" + (batch.getStatus() == null ? "UNKNOWN" : batch.getStatus().name()));
        if (batch.getFailReason() != null) {
            evidence.add("批次失败原因=" + batch.getFailReason());
        }
        if (batch.getLifecycleProfile() == null) {
            evidence.add("KL1标识缺失（存量未迁移批次），不做推断");
        } else {
            evidence.add("KL1 F=" + batch.getFirstIssuedAt() + ", B=" + batch.getAckDeadlineAt());
        }
        items.forEach(item -> {
            if (item.getDirectoryKeyState() != null) {
                evidence.add("用途" + item.getPurpose() + "目录状态=" + item.getDirectoryKeyState());
            }
            evidence.add("用途" + item.getPurpose() + "设备确认=" + item.getDeviceResult());
        });
        if (lease != null) {
            evidence.add("最近租约 seq=" + lease.getLeaseSeq() + ", expireAt=" + lease.getExpireAt());
        }

        return ProvisioningDiagnosisVo.builder()
                .requestId(batch.getRequestId())
                .deviceSn(batch.getDeviceSn())
                .businessDomain(batch.getBusinessDomain())
                .status(batch.getStatus() == null ? null : batch.getStatus().name())
                .blockingLevel(blocking.level())
                .blockingReason(blocking.reason())
                .clearable(isClearable(batch))
                .lifecycleProfile(batch.getLifecycleProfile())
                .firstIssuedAt(batch.getFirstIssuedAt())
                .ackDeadlineAt(batch.getAckDeadlineAt())
                .leaseSeq(batch.getLeaseSeq())
                .leaseExpireAt(lease == null ? null : lease.getExpireAt())
                .terminalReason(batch.getTerminalReason())
                .items(items)
                .evidence(evidence)
                .build();
    }

    /**
     * 是否允许清阻断：仅 RECONCILE_REQUIRED / FAILED。
     */
    static boolean isClearable(ProvisioningBatch batch) {
        ProvisioningBatch.BatchState state = batch.getStatus();
        return state == ProvisioningBatch.BatchState.RECONCILE_REQUIRED
                || state == ProvisioningBatch.BatchState.FAILED;
    }

    private List<ProvisioningItemVo> buildItems(ProvisioningBatch batch) {
        if (batch.getId() == null) {
            return List.of();
        }
        return batchRepository.listItemsByProvisioningId(batch.getId()).stream()
                .map(this::toItemVo)
                .toList();
    }

    private ProvisioningItemVo toItemVo(ProvisioningItem item) {
        Optional<DeviceBusinessKey> directory = item.getKeyId() == null
                ? Optional.empty()
                : businessKeyRepository.findByKeyId(item.getKeyId());
        return ProvisioningItemVo.builder()
                .purpose(item.getPurpose())
                .businessKeyVersion(item.getBusinessKeyVersion())
                .keyId(item.getKeyId())
                .rootKeyVersion(item.getRootKeyVersion())
                .derivationVersion(item.getDerivationVersion())
                .envelopeFormat(item.getEnvelopeFormat())
                .deviceResult(item.getDeviceResult() == null ? null : item.getDeviceResult().name())
                .confirmedAt(item.getConfirmedAt())
                .directoryKeyState(directory.map(k -> k.getKeyState().name()).orElse(null))
                .directoryBusinessKeyVersion(directory.map(DeviceBusinessKey::getBusinessKeyVersion).orElse(null))
                .build();
    }

    private ProvisioningLeaseVo buildLease(ProvisioningBatch batch) {
        Integer seq = batch.getLeaseSeq();
        if (batch.getId() == null || seq == null || seq <= 0) {
            return null;
        }
        return leaseRepository.findByProvisioningAndSeq(batch.getId(), seq)
                .map(this::toLeaseVo)
                .orElse(null);
    }

    private ProvisioningLeaseVo toLeaseVo(KeyProvisioningLease lease) {
        return ProvisioningLeaseVo.builder()
                .leaseSeq(lease.getLeaseSeq())
                .issuedAt(lease.getIssuedAt())
                .expireAt(lease.getExpireAt())
                .messageId(lease.getMessageId())
                .build();
    }

    /**
     * 阻塞判定：批次级优先于目录行级（目录行阻塞在批次仍在推进时同样要指出）。
     */
    private Blocking evaluateBlocking(ProvisioningBatch batch, List<ProvisioningItemVo> items) {
        ProvisioningBatch.BatchState state = batch.getStatus();
        if (state == ProvisioningBatch.BatchState.RECONCILE_REQUIRED
                || state == ProvisioningBatch.BatchState.FAILED) {
            return new Blocking("BATCH", "批次状态=" + state.name()
                    + (batch.getFailReason() == null ? "" : "；原因=" + batch.getFailReason()));
        }
        if (state == ProvisioningBatch.BatchState.EXPIRED) {
            return new Blocking("BATCH", "批次已过期终态（ACK_TIMEOUT 等），终态不复活");
        }
        for (ProvisioningItemVo item : items) {
            String directoryState = item.getDirectoryKeyState();
            if ("RECONCILE_REQUIRED".equals(directoryState)
                    || "PENDING_RECOVERY".equals(directoryState)
                    || "FAILED".equals(directoryState)) {
                return new Blocking("LOCAL_DIRECTORY",
                        "用途" + item.getPurpose() + "目录行状态=" + directoryState);
            }
        }
        return new Blocking("NONE", null);
    }

    private boolean isOpen(ProvisioningBatch batch) {
        ProvisioningBatch.BatchState state = batch.getStatus();
        return state == ProvisioningBatch.BatchState.PREPARING
                || state == ProvisioningBatch.BatchState.WAIT_DEVICE_ACK
                || state == ProvisioningBatch.BatchState.RECONCILE_REQUIRED;
    }

    /**
     * 阻塞判定结果。
     */
    private record Blocking(String level, String reason) {
    }
}
