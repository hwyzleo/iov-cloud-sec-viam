package net.hwyz.iov.cloud.sec.viam.service.application.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.sec.viam.service.common.util.ViamUtils;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.CertificateOperation;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.CertificateOperationRepository;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Optional;

/**
 * 证书人工操作审计记录器（SEC-VIAM-DSN-CR-002 / FR-VIAM-007 / D-VIAM-013）
 * <p>
 * 统一落不可变操作事实：只保存脱敏要素，不保存 CSR 全文、证书本体与密钥材料。
 * 写操作由调用方在业务事务内调用，保证「状态变更 + 审计」同事务；
 * 读敏感材料（证书本体）由调用方在审计写失败时拒绝返回材料（fail-closed）。
 * </p>
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CertificateOperationRecorder {

    private final CertificateOperationRepository operationRepository;

    /**
     * 记录一次证书操作（operationId 作为幂等键）。
     *
     * @param action         操作类型
     * @param requestId      关联证书申请 requestId
     * @param operatorId     服务端解析的操作人ID
     * @param operatorName   操作人姓名
     * @param reason         人工原因
     * @param ticketNo       关联工单号
     * @param originalRequestId MES原请求号（可空）
     * @param beforeStatus   操作前状态
     * @param afterStatus    操作后状态
     * @param result         结果
     * @param errorCode      失败错误码（可空）
     * @param csrDerBase64   CSR（仅用于计算指纹摘要，绝不落库）
     * @param sourceIp       来源IP（可空）
     * @param userAgent      终端UA（可空）
     * @return 已落库的操作事实
     */
    public CertificateOperation record(CertificateOperation.Action action,
                                       String requestId,
                                       String operatorId,
                                       String operatorName,
                                       String reason,
                                       String ticketNo,
                                       String originalRequestId,
                                       String beforeStatus,
                                       String afterStatus,
                                       CertificateOperation.Result result,
                                       String errorCode,
                                       String csrDerBase64,
                                       String sourceIp,
                                       String userAgent) {
        Instant now = Instant.now();
        CertificateOperation operation = CertificateOperation.builder()
                .operationId(newOperationId(requestId, action, now))
                .requestId(requestId)
                .action(action)
                .operatorId(operatorId)
                .operatorName(operatorName)
                .reason(reason)
                .ticketNo(ticketNo)
                .originalRequestId(originalRequestId)
                .beforeStatus(beforeStatus)
                .afterStatus(afterStatus)
                .requestDigest(buildRequestDigest(action, requestId, csrDerBase64))
                .result(result)
                .errorCode(errorCode)
                .sourceIp(sourceIp)
                .userAgent(userAgent)
                .occurredAt(now)
                .build();
        operationRepository.save(operation);
        log.info("证书操作审计: action={}, requestId={}, result={}, operator={}",
                action, requestId, result, operatorId);
        return operation;
    }

    /**
     * 按操作ID查询已有审计事实（供幂等判定/回放）。
     */
    public Optional<CertificateOperation> findByOperationId(String operationId) {
        return operationRepository.findByOperationId(operationId);
    }

    /**
     * 操作ID = requestId:action:时间戳（唯一，不依赖外部自报）。
     */
    private String newOperationId(String requestId, CertificateOperation.Action action, Instant now) {
        return requestId + ":" + action + ":" + now.toEpochMilli();
    }

    /**
     * 请求摘要 = SHA-256(action|requestId|CSR指纹)；不含 CSR 全文、证书本体。
     */
    private String buildRequestDigest(CertificateOperation.Action action, String requestId, String csrDerBase64) {
        String csrFingerprint = (csrDerBase64 == null || csrDerBase64.isBlank())
                ? "-" : ViamUtils.sha256Hex(csrDerBase64);
        return ViamUtils.sha256Hex(action.name() + "|" + requestId + "|" + csrFingerprint);
    }
}
