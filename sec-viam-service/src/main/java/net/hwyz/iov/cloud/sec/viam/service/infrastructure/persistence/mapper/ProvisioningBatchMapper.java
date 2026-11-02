package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.ProvisioningBatchPo;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/**
 * 业务密钥开通批次 DAO（SEC-VIAM-DSN-CR-001）
 *
 * @author hwyz_leo
 */
@Mapper
public interface ProvisioningBatchMapper extends BaseMapper<ProvisioningBatchPo> {

    ProvisioningBatchPo selectByRequestId(@Param("requestId") String requestId);

    /** 行锁读取（KL1 租约签发/ACK 线性化；调用方须在事务内） */
    ProvisioningBatchPo selectByRequestIdForUpdate(@Param("requestId") String requestId);
}
