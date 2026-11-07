package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.ViamOutboxPo;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;

import java.time.LocalDateTime;
import java.util.List;

/**
 * VIAM Outbox DAO（SEC-VIAM-DSN-CR-001 / D-VIAM-008）
 * <p>
 * 写入端 {@link net.hwyz.iov.cloud.sec.viam.service.infrastructure.outbox.ViamOutboxWriter} 与
 * 发布端 {@link net.hwyz.iov.cloud.sec.viam.service.infrastructure.outbox.ViamOutboxRelay} 共用；
 * 发布状态机：PENDING → PUBLISHED / FAILED_RETRYABLE → DEAD（与 DDL 注释一致）。
 *
 * @author hwyz_leo
 */
@Mapper
public interface ViamOutboxMapper extends BaseMapper<ViamOutboxPo> {

    /**
     * 按事件ID查询（幂等）。
     */
    ViamOutboxPo selectByEventId(@Param("eventId") String eventId);

    /**
     * 扫描待发布事件：PENDING/FAILED_RETRYABLE 且退避时间已到，按 id 升序取一批。
     *
     * @param limit 批量上限
     * @return 待发布事件列表
     */
    @Select("SELECT * FROM tb_viam_outbox "
            + "WHERE row_valid = 1 "
            + "AND publish_state IN ('PENDING', 'FAILED_RETRYABLE') "
            + "AND (next_retry_time IS NULL OR next_retry_time <= NOW()) "
            + "ORDER BY id ASC "
            + "LIMIT #{limit}")
    List<ViamOutboxPo> selectPending(@Param("limit") int limit);

    /**
     * 标记发布成功（幂等：eventId 维度）。
     */
    @Update("UPDATE tb_viam_outbox SET "
            + "publish_state = 'PUBLISHED', "
            + "published_at = #{publishedAt}, "
            + "last_error = NULL "
            + "WHERE event_id = #{eventId} AND row_valid = 1")
    int markPublished(@Param("eventId") String eventId, @Param("publishedAt") LocalDateTime publishedAt);

    /**
     * 标记发布失败待重试（退避时间由调用方计算）。
     */
    @Update("UPDATE tb_viam_outbox SET "
            + "publish_state = 'FAILED_RETRYABLE', "
            + "retry_count = #{retryCount}, "
            + "next_retry_time = #{nextRetryTime}, "
            + "last_error = #{error} "
            + "WHERE event_id = #{eventId} AND row_valid = 1")
    int markFailedRetryable(@Param("eventId") String eventId, @Param("retryCount") int retryCount,
                            @Param("nextRetryTime") LocalDateTime nextRetryTime,
                            @Param("error") String error);

    /**
     * 标记永久失败（非法记录/重试耗尽，终态终止重试）。
     */
    @Update("UPDATE tb_viam_outbox SET "
            + "publish_state = 'DEAD', "
            + "last_error = #{error} "
            + "WHERE event_id = #{eventId} AND row_valid = 1")
    int markDead(@Param("eventId") String eventId, @Param("error") String error);
}
