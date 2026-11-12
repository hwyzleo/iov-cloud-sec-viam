package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.ProvisioningBatchPo;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

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

    /** 按设备+域查未终结批次（SEC-VIAM-DSN-CR-002 / D-VIAM-017） */
    ProvisioningBatchPo selectOpenByDeviceSnAndDomain(@Param("deviceSn") String deviceSn,
                                                      @Param("businessDomain") String businessDomain);

    /** 按设备+域列出批次（可选含历史终结批次），发起时间倒序（SEC-VIAM-DSN-CR-002 / D-VIAM-017） */
    List<ProvisioningBatchPo> selectByDeviceSnAndDomain(@Param("deviceSn") String deviceSn,
                                                        @Param("businessDomain") String businessDomain,
                                                        @Param("includeTerminal") boolean includeTerminal,
                                                        @Param("limit") int limit);
}
