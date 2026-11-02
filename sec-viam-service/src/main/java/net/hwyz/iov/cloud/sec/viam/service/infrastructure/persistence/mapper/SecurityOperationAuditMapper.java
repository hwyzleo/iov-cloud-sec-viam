package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.SecurityOperationAuditPo;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface SecurityOperationAuditMapper extends BaseMapper<SecurityOperationAuditPo> {

    SecurityOperationAuditPo selectByOperationId(@Param("operationId") String operationId);
}
