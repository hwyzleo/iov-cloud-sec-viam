package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.mapper;

import net.hwyz.iov.cloud.framework.mysql.dao.BaseDao;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.ViamInboxPo;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/**
 * VIAM Inbox DAO（SEC-VIAM-DSN-CR-001）
 *
 * @author hwyz_leo
 */
@Mapper
public interface ViamInboxMapper extends BaseDao<ViamInboxPo, Long> {

    /**
     * 按事件ID查询（去重）。
     */
    ViamInboxPo selectByEventId(@Param("eventId") String eventId);
}
