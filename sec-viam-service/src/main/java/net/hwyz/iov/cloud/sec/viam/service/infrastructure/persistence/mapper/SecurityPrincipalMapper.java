package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.mapper;

import net.hwyz.iov.cloud.framework.mysql.dao.BaseDao;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.SecurityPrincipalPo;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/**
 * 安全主体 DAO（SEC-VIAM-DSN-CR-001）
 *
 * @author hwyz_leo
 */
@Mapper
public interface SecurityPrincipalMapper extends BaseDao<SecurityPrincipalPo, Long> {

    /**
     * 按 principalId 查询。
     */
    SecurityPrincipalPo selectByPrincipalId(@Param("principalId") String principalId);

    /**
     * 按 hsmUid 查询。
     */
    SecurityPrincipalPo selectByHsmUid(@Param("hsmUid") String hsmUid);
}
