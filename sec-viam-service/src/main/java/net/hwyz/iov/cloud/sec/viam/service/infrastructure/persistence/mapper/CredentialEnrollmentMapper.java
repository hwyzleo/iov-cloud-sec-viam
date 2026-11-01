package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.mapper;

import net.hwyz.iov.cloud.framework.mysql.dao.BaseDao;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.CredentialEnrollmentPo;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.time.LocalDateTime;
import java.util.List;

/**
 * 设备证书登记 DAO（SEC-VIAM-DSN-CR-001）
 *
 * @author hwyz_leo
 */
@Mapper
public interface CredentialEnrollmentMapper extends BaseDao<CredentialEnrollmentPo, Long> {

    CredentialEnrollmentPo selectByRequestId(@Param("requestId") String requestId);

    CredentialEnrollmentPo selectByCertSn(@Param("certSn") String certSn);

    CredentialEnrollmentPo selectByPkiRequestId(@Param("pkiRequestId") String pkiRequestId);

    CredentialEnrollmentPo selectByVinAndUidAndSpkiAndProfile(
            @Param("vin") String vin, @Param("hsmUid") String hsmUid,
            @Param("publicKeySha256") String publicKeySha256, @Param("certificateProfile") String certificateProfile);

    CredentialEnrollmentPo selectKeyConflictByVinAndUidAndProfile(
            @Param("vin") String vin, @Param("hsmUid") String hsmUid,
            @Param("publicKeySha256") String publicKeySha256, @Param("certificateProfile") String certificateProfile);

    CredentialEnrollmentPo selectActiveByVinAndDeviceCategory(
            @Param("vin") String vin, @Param("deviceCategory") String deviceCategory);

    List<CredentialEnrollmentPo> selectByDeviceSn(@Param("deviceSn") String deviceSn);

    List<CredentialEnrollmentPo> selectUpdatedAfter(@Param("updatedAfter") LocalDateTime updatedAfter,
                                                    @Param("limit") int limit);

    int supersedeActiveByDeviceSnAndProfile(@Param("deviceSn") String deviceSn,
                                            @Param("certificateProfile") String certificateProfile,
                                            @Param("excludeRequestId") String excludeRequestId);
}
