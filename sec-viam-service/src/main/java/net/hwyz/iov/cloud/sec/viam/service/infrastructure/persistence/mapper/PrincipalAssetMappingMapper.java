package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.PrincipalAssetMappingPo;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

/**
 * 安全主体资产映射 DAO（SEC-VIAM-DSN-CR-001）
 *
 * @author hwyz_leo
 */
@Mapper
public interface PrincipalAssetMappingMapper extends BaseMapper<PrincipalAssetMappingPo> {

    /**
     * 按主体ID查询 ACTIVE 映射列表。
     */
    List<PrincipalAssetMappingPo> selectActiveByPrincipalId(@Param("principalId") String principalId);

    /**
     * 按 VIN 查询 ACTIVE 映射列表。
     */
    List<PrincipalAssetMappingPo> selectActiveByVin(@Param("vin") String vin);

    /**
     * 按设备SN 查询 ACTIVE 映射。
     */
    PrincipalAssetMappingPo selectActiveByDeviceSn(@Param("deviceSn") String deviceSn);
}
