-- ============================================================================
-- V3 证书管理面查询索引（SEC-VIAM-DSN-CR-002 / FR-VIAM-002 / D-VIAM-012）
-- 原则：只增量新增索引，不修改既有列、约束与数据；证书操作审计表
-- tb_viam_certificate_operation 已在 V1 建立，本迁移不重复建表。
-- 回退需 DBA 显式 DROP INDEX，且不得连带删除审计数据。
-- ============================================================================

-- MPT 列表按状态 + 修改时间过滤（默认排序 create_time DESC，状态是高频等值条件）
ALTER TABLE `tb_viam_credential_enrollment`
  ADD INDEX `idx_cert_status_modify` (`cert_status`, `modify_time`);

-- MPT 列表按来源系统 + 状态过滤（MES / MPT_COMPENSATION 运维口径）
ALTER TABLE `tb_viam_credential_enrollment`
  ADD INDEX `idx_source_status` (`source_system`, `cert_status`);
