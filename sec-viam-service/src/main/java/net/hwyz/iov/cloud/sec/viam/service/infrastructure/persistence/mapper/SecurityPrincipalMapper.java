package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.SecurityPrincipalPo;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/**
 * 安全主体 DAO（SEC-VIAM-DSN-CR-001）
 *
 * @author hwyz_leo
 */
@Mapper
public interface SecurityPrincipalMapper extends BaseMapper<SecurityPrincipalPo> {

    /**
     * 按 principalId 查询。
     */
    SecurityPrincipalPo selectByPrincipalId(@Param("principalId") String principalId);

    /**
     * 按 hsmUid 查询。
     */
    SecurityPrincipalPo selectByHsmUid(@Param("hsmUid") String hsmUid);
}
