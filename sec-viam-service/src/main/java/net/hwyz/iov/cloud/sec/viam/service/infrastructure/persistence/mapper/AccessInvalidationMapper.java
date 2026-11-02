package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.AccessInvalidationPo;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.time.LocalDateTime;
import java.util.List;

/**
 * 访问失效执行跟踪 DAO（SEC-VIAM-DSN-CR-001 / G-3）
 *
 * @author hwyz_leo
 */
@Mapper
public interface AccessInvalidationMapper extends BaseMapper<AccessInvalidationPo> {

    AccessInvalidationPo selectByInvalidationId(@Param("invalidationId") String invalidationId);

    List<AccessInvalidationPo> selectPendingBefore(@Param("now") LocalDateTime now, @Param("limit") int limit);
}
