package net.hwyz.iov.cloud.sec.viam.service.domain.repository;

import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.CertificateOperation;

import java.util.List;
import java.util.Optional;

/**
 * 证书人工操作审计仓储（SEC-VIAM-DSN-CR-002 / FR-VIAM-007 / D-VIAM-013）
 *
 * @author hwyz_leo
 */
public interface CertificateOperationRepository {

    /**
     * 按操作ID查询（幂等键）。
     */
    Optional<CertificateOperation> findByOperationId(String operationId);

    /**
     * 按证书申请 requestId 查询时间线（发生时间升序）。
     */
    List<CertificateOperation> listByRequestId(String requestId);

    /**
     * 保存审计事实。
     */
    void save(CertificateOperation operation);
}
