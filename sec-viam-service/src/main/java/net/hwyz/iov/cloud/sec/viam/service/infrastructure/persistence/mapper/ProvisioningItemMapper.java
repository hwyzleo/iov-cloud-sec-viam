package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.ProvisioningItemPo;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

/**
 * 业务密钥开通批次明细 DAO（SEC-VIAM-DSN-CR-001）
 *
 * @author hwyz_leo
 */
@Mapper
public interface ProvisioningItemMapper extends BaseMapper<ProvisioningItemPo> {

    List<ProvisioningItemPo> selectItemsByProvisioningId(@Param("provisioningId") Long provisioningId);
}
