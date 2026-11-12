package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.repository;

import lombok.RequiredArgsConstructor;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.CertificateOperation;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.CertificateOperationRepository;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.converter.CertificateOperationConverter;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.mapper.CertificateOperationMapper;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.CertificateOperationPo;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * 证书人工操作审计仓储实现（SEC-VIAM-DSN-CR-002 / D-VIAM-013）
 *
 * @author hwyz_leo
 */
@Repository
@RequiredArgsConstructor
public class CertificateOperationRepositoryImpl implements CertificateOperationRepository {

    private final CertificateOperationMapper mapper;

    @Override
    public Optional<CertificateOperation> findByOperationId(String operationId) {
        return Optional.ofNullable(
                CertificateOperationConverter.toEntity(mapper.selectByOperationId(operationId)));
    }

    @Override
    public List<CertificateOperation> listByRequestId(String requestId) {
        return mapper.selectByRequestId(requestId).stream()
                .map(CertificateOperationConverter::toEntity)
                .collect(Collectors.toList());
    }

    @Override
    public void save(CertificateOperation operation) {
        CertificateOperationPo po = CertificateOperationConverter.toPo(operation);
        int inserted = mapper.insert(po);
        if (inserted != 1) {
            throw new IllegalStateException("证书操作审计写入未影响一行: requestId=" + operation.getRequestId()
                    + ", action=" + operation.getAction());
        }
        operation.setId(po.getId());
    }
}
