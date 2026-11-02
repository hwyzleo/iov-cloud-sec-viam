package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.mapper;

import net.hwyz.iov.cloud.framework.mysql.dao.BaseDao;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.DeviceBusinessKeyPo;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/**
 * 设备业务密钥目录 DAO（SEC-VIAM-DSN-CR-001）
 *
 * @author hwyz_leo
 */
@Mapper
public interface DeviceBusinessKeyMapper extends BaseDao<DeviceBusinessKeyPo, Long> {

    DeviceBusinessKeyPo selectByKeyId(@Param("keyId") String keyId);

    DeviceBusinessKeyPo selectByKeyIdForUpdate(@Param("keyId") String keyId);

    DeviceBusinessKeyPo selectActiveByContext(@Param("deviceSn") String deviceSn,
                                              @Param("businessDomain") String businessDomain,
                                              @Param("purpose") String purpose);

    DeviceBusinessKeyPo selectByRequestIdAndPurpose(@Param("requestId") String requestId,
                                                    @Param("purpose") String purpose);
}
