package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.mapper;

import net.hwyz.iov.cloud.framework.mysql.dao.BaseDao;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.KeyProvisioningLeasePo;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

/**
 * KL1 交付租约 DAO（SEC-VIAM-DSN-CR-001）
 *
 * @author hwyz_leo
 */
@Mapper
public interface KeyProvisioningLeaseMapper extends BaseDao<KeyProvisioningLeasePo, Long> {

    List<KeyProvisioningLeasePo> selectByProvisioningId(@Param("provisioningId") Long provisioningId);

    KeyProvisioningLeasePo selectByProvisioningAndSeq(@Param("provisioningId") Long provisioningId,
                                                      @Param("leaseSeq") Integer leaseSeq);

    KeyProvisioningLeasePo selectByMessageId(@Param("messageId") String messageId);
}
