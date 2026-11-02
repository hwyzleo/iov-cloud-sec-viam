package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.ViamInboxPo;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/**
 * VIAM Inbox DAO（SEC-VIAM-DSN-CR-001）
 *
 * @author hwyz_leo
 */
@Mapper
public interface ViamInboxMapper extends BaseMapper<ViamInboxPo> {

    /**
     * 按事件ID查询（去重）。
     */
    ViamInboxPo selectByEventId(@Param("eventId") String eventId);
}
