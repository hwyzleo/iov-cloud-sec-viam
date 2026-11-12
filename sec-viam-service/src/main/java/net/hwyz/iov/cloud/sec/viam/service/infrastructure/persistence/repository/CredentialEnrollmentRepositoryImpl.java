package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.repository;

import lombok.RequiredArgsConstructor;
import com.github.pagehelper.Page;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.CredentialEnrollment;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.query.CertificatePage;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.query.CertificateQuery;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.CredentialEnrollmentRepository;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.converter.CredentialEnrollmentConverter;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.mapper.CredentialEnrollmentMapper;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.CredentialEnrollmentPo;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * 设备证书登记仓储实现（SEC-VIAM-DSN-CR-001）
 *
 * @author hwyz_leo
 */
@Repository
@RequiredArgsConstructor
public class CredentialEnrollmentRepositoryImpl implements CredentialEnrollmentRepository {

    private static final ZoneId UTC = ZoneId.of("UTC");

    private static java.time.LocalDateTime toLdt(Instant instant) {
        return instant == null ? null : java.time.LocalDateTime.ofInstant(instant, UTC);
    }

    private final CredentialEnrollmentMapper mapper;

    @Override
    public Optional<CredentialEnrollment> findByRequestId(String requestId) {
        return Optional.ofNullable(CredentialEnrollmentConverter.toEntity(mapper.selectByRequestId(requestId)));
    }

    @Override
    public Optional<CredentialEnrollment> findByCertSn(String certSn) {
        return Optional.ofNullable(CredentialEnrollmentConverter.toEntity(mapper.selectByCertSn(certSn)));
    }

    @Override
    public Optional<CredentialEnrollment> findByVinAndUidAndSpkiAndProfile(
            String vin, String hsmUid, String publicKeySha256, String profile) {
        return Optional.ofNullable(CredentialEnrollmentConverter.toEntity(
                mapper.selectByVinAndUidAndSpkiAndProfile(vin, hsmUid, publicKeySha256, profile)));
    }

    @Override
    public Optional<CredentialEnrollment> findKeyConflictByVinAndUidAndProfile(
            String vin, String hsmUid, String publicKeySha256, String profile) {
        return Optional.ofNullable(CredentialEnrollmentConverter.toEntity(
                mapper.selectKeyConflictByVinAndUidAndProfile(vin, hsmUid, publicKeySha256, profile)));
    }

    @Override
    public Optional<CredentialEnrollment> findActiveByVinAndDeviceCategory(String vin, String deviceCategory) {
        return Optional.ofNullable(CredentialEnrollmentConverter.toEntity(
                mapper.selectActiveByVinAndDeviceCategory(vin, deviceCategory)));
    }

    @Override
    public List<CredentialEnrollment> listByDeviceSn(String deviceSn) {
        return mapper.selectByDeviceSn(deviceSn).stream()
                .map(CredentialEnrollmentConverter::toEntity)
                .collect(Collectors.toList());
    }

    @Override
    public List<CredentialEnrollment> listUpdatedAfter(Instant updatedAfter, int limit) {
        return mapper.selectUpdatedAfter(java.time.LocalDateTime.ofInstant(updatedAfter, UTC), limit).stream()
                .map(CredentialEnrollmentConverter::toEntity)
                .collect(Collectors.toList());
    }

    @Override
    public CertificatePage page(CertificateQuery query) {
        List<CredentialEnrollmentPo> pos = mapper.selectByQuery(
                query.vin(), query.deviceSn(), query.certSn(), query.requestId(),
                query.status(), query.sourceSystem(),
                toLdt(query.beginTime()), toLdt(query.endTime()));
        long total = pos instanceof Page<?> pageable ? pageable.getTotal() : pos.size();
        List<CredentialEnrollment> items = pos.stream()
                .map(CredentialEnrollmentConverter::toEntity)
                .collect(Collectors.toList());
        return new CertificatePage(items, total);
    }

    @Override
    public void insert(CredentialEnrollment enrollment) {
        mapper.insert(CredentialEnrollmentConverter.toPo(enrollment));
    }

    @Override
    public void update(CredentialEnrollment enrollment) {
        CredentialEnrollmentPo po = CredentialEnrollmentConverter.toPo(enrollment);
        CredentialEnrollmentPo existing = mapper.selectByRequestId(enrollment.getRequestId());
        if (existing != null) {
            po.setId(existing.getId());
            // FW-MYSQL-DSN-CR-003：updatePo → updateById；原版本须由 fresh 读取携带（乐观锁 CAS），并检查影响行数
            po.setRowVersion(existing.getRowVersion());
            int updated = mapper.updateById(po);
            if (updated != 1) {
                throw new IllegalStateException("更新未影响一行（不存在/已删除/版本冲突）: id=" + existing.getId());
            }
        }
    }

    @Override
    public void supersedeActiveByDeviceSnAndProfile(String deviceSn, String profile, String excludeRequestId) {
        mapper.supersedeActiveByDeviceSnAndProfile(deviceSn, profile, excludeRequestId);
    }
}
