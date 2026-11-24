-- =============================================================================
-- SEC-VIAM-DSN-CR-006 / D-VIAM-032：同一 device_sn 同时最多一条 ACTIVE 映射
--
-- 背景：绑定事实自动登记后，换件/重绑可能产生同 SN 多条 ACTIVE；应用层已做收敛，
--       本索引作为最终兜底（active_flag 为既有 STORED GENERATED 列，status='ACTIVE' 时为 1）。
-- 上线前置：先核对并清理存量冲突，否则本迁移会失败：
--   SELECT device_sn, COUNT(*) FROM tb_viam_principal_asset_mapping
--    WHERE status = 'ACTIVE' AND row_valid = 1 GROUP BY device_sn HAVING COUNT(*) > 1;
-- 回滚：ALTER TABLE tb_viam_principal_asset_mapping DROP INDEX uk_device_sn_active;
-- =============================================================================

ALTER TABLE `tb_viam_principal_asset_mapping`
    ADD UNIQUE KEY `uk_device_sn_active` (`device_sn`, `active_flag`);
