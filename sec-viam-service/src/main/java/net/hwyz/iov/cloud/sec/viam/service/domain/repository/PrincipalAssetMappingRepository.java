package net.hwyz.iov.cloud.sec.viam.service.domain.repository;

import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.PrincipalAssetMapping;

import java.util.List;
import java.util.Optional;

/**
 * 安全主体资产映射仓储（SEC-VIAM-DSN-CR-001 / D-VIAM-003）
 *
 * @author hwyz_leo
 */
public interface PrincipalAssetMappingRepository {

    /**
     * 按主体ID + VIN 查询当前映射。
     */
    Optional<PrincipalAssetMapping> findByPrincipalAndVin(String principalId, String vin);

    /**
     * 按主体ID查询 ACTIVE 映射列表。
     */
    List<PrincipalAssetMapping> listActiveByPrincipalId(String principalId);

    /**
     * 按 VIN 查询 ACTIVE 映射列表。
     */
    List<PrincipalAssetMapping> listActiveByVin(String vin);

    /**
     * 按设备SN 查询 ACTIVE 映射。
     */
    Optional<PrincipalAssetMapping> findActiveByDeviceSn(String deviceSn);

    /**
     * 保存。
     */
    void save(PrincipalAssetMapping mapping);
}
