package net.hwyz.iov.cloud.sec.viam.service.domain.repository;

import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SecurityPrincipal;

import java.util.List;
import java.util.Optional;

/**
 * 安全主体仓储（SEC-VIAM-DSN-CR-001 / FR-VIAM-001）
 *
 * @author hwyz_leo
 */
public interface SecurityPrincipalRepository {

    /**
     * 按 principalId 查询。
     */
    Optional<SecurityPrincipal> findByPrincipalId(String principalId);

    /**
     * 按 hsmUid 查询。
     */
    Optional<SecurityPrincipal> findByHsmUid(String hsmUid);

    /**
     * 保存（插入或更新）。
     */
    void save(SecurityPrincipal principal);

    /**
     * 列出全部主体（对账/迁移用，分页）。
     */
    List<SecurityPrincipal> listAll(int offset, int limit);
}
