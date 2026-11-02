package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.mapper;

import net.hwyz.iov.cloud.framework.mysql.dao.BaseDao;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.SecurityOperationAuditPo;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface SecurityOperationAuditMapper extends BaseDao<SecurityOperationAuditPo, Long> {

    SecurityOperationAuditPo selectByOperationId(@Param("operationId") String operationId);
}
