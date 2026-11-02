package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.DeviceOnboardingPo;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/**
 * 安全开通状态 DAO（SEC-VIAM-DSN-CR-001）
 *
 * @author hwyz_leo
 */
@Mapper
public interface DeviceOnboardingMapper extends BaseMapper<DeviceOnboardingPo> {

    /**
     * 按主体ID查询。
     */
    DeviceOnboardingPo selectByPrincipalId(@Param("principalId") String principalId);
}
