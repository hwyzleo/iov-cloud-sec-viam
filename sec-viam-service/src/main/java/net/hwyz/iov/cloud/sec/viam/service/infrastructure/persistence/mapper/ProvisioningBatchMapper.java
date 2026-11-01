package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.mapper;

import net.hwyz.iov.cloud.framework.mysql.dao.BaseDao;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.ProvisioningBatchPo;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/**
 * 业务密钥开通批次 DAO（SEC-VIAM-DSN-CR-001）
 *
 * @author hwyz_leo
 */
@Mapper
public interface ProvisioningBatchMapper extends BaseDao<ProvisioningBatchPo, Long> {

    ProvisioningBatchPo selectByRequestId(@Param("requestId") String requestId);
}
