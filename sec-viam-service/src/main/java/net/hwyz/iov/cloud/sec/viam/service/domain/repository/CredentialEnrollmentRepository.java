package net.hwyz.iov.cloud.sec.viam.service.domain.repository;

import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.CredentialEnrollment;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * 设备证书登记仓储（SEC-VIAM-DSN-CR-001 / FR-VIAM-002）
 *
 * @author hwyz_leo
 */
public interface CredentialEnrollmentRepository {

    /**
     * 按 requestId 查询。
     */
    Optional<CredentialEnrollment> findByRequestId(String requestId);

    /**
     * 按证书序列号查询。
     */
    Optional<CredentialEnrollment> findByCertSn(String certSn);

    /**
     * 同身份同公钥幂等复用查询。
     */
    Optional<CredentialEnrollment> findByVinAndUidAndSpkiAndProfile(
            String vin, String hsmUid, String publicKeySha256, String profile);

    /**
     * 换钥冲突查询。
     */
    Optional<CredentialEnrollment> findKeyConflictByVinAndUidAndProfile(
            String vin, String hsmUid, String publicKeySha256, String profile);

    /**
     * 按 VIN + 设备类别查询 ACTIVE 证书。
     */
    Optional<CredentialEnrollment> findActiveByVinAndDeviceCategory(String vin, String deviceCategory);

    /**
     * 按设备SN查询证书列表。
     */
    List<CredentialEnrollment> listByDeviceSn(String deviceSn);

    /**
     * 更新时间大于指定时间的证书列表（对账）。
     */
    List<CredentialEnrollment> listUpdatedAfter(Instant updatedAfter, int limit);

    /**
     * 插入。
     */
    void insert(CredentialEnrollment enrollment);

    /**
     * 更新。
     */
    void update(CredentialEnrollment enrollment);

    /**
     * 作废同设备同Profile既有ACTIVE（安装确认激活前）。
     */
    void supersedeActiveByDeviceSnAndProfile(String deviceSn, String profile, String excludeRequestId);
}
