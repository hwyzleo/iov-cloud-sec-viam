package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.ViamOutboxPo;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/**
 * VIAM Outbox DAO（SEC-VIAM-DSN-CR-001）
 *
 * @author hwyz_leo
 */
@Mapper
public interface ViamOutboxMapper extends BaseMapper<ViamOutboxPo> {

    /**
     * 按事件ID查询（幂等）。
     */
    ViamOutboxPo selectByEventId(@Param("eventId") String eventId);
}
