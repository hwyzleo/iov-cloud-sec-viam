package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.mapper;

import net.hwyz.iov.cloud.framework.mysql.dao.BaseDao;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.DecisionAuditPo;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/**
 * 准入裁决审计 DAO（SEC-VIAM-DSN-CR-001）
 *
 * @author hwyz_leo
 */
@Mapper
public interface DecisionAuditMapper extends BaseDao<DecisionAuditPo, Long> {

    /**
     * 按准入裁决ID查询。
     */
    DecisionAuditPo selectByAdmissionDecisionId(@Param("admissionDecisionId") String admissionDecisionId);
}
