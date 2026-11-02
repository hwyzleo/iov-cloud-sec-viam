package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.SuccessfulDeviceLoginPo;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.time.LocalDateTime;

/**
 * 成功接入记录 DAO（SEC-VIAM-DSN-CR-001）
 *
 * @author hwyz_leo
 */
@Mapper
public interface SuccessfulDeviceLoginMapper extends BaseMapper<SuccessfulDeviceLoginPo> {

    /**
     * 按 loginId 查询。
     */
    SuccessfulDeviceLoginPo selectByLoginId(@Param("loginId") String loginId);

    /**
     * 按主体查询首次接入时间。
     */
    LocalDateTime selectFirstLoginTime(@Param("principalId") String principalId);

    /**
     * 按主体查询最近接入时间。
     */
    LocalDateTime selectLastLoginTime(@Param("principalId") String principalId);
}
