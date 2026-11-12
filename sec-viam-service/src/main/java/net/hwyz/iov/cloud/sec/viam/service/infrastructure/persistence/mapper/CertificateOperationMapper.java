package net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.persistence.po.CertificateOperationPo;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

/**
 * 证书人工操作审计 DAO（SEC-VIAM-DSN-CR-002 / D-VIAM-013）
 *
 * @author hwyz_leo
 */
@Mapper
public interface CertificateOperationMapper extends BaseMapper<CertificateOperationPo> {

    /**
     * 按操作ID查询（幂等键）。
     */
    CertificateOperationPo selectByOperationId(@Param("operationId") String operationId);

    /**
     * 按证书申请 requestId 查询时间线（发生时间升序）。
     */
    List<CertificateOperationPo> selectByRequestId(@Param("requestId") String requestId);
}
