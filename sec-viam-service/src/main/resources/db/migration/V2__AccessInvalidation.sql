-- ============================================================================
-- V2 访问失效执行跟踪 + 安全操作审计 + 安全状态版本（SEC-VIAM-DSN-CR-001 / FR-VIAM-008 / T05 / G-3）
-- 原则：V1 已在需保留环境执行过，本迁移只增量新增，不修改已应用表结构。
-- 执行跟踪表保存可变的重试/回执状态；审计表保存不可篡改的操作事实。
-- ============================================================================

-- ================= tb_viam_onboarding 增加安全状态版本（block/unblock/retire 单调递增） =================
ALTER TABLE `tb_viam_onboarding`
  ADD COLUMN IF NOT EXISTS `security_version` bigint DEFAULT '0' COMMENT '安全状态版本（安全状态变更单调递增；失效事件携带）' AFTER `activate_version`;

-- ================= 访问失效执行跟踪（可变状态：回执/重试/超时/对账） =================
CREATE TABLE IF NOT EXISTS `tb_viam_access_invalidation` (
  `id` bigint NOT NULL AUTO_INCREMENT COMMENT '主键',
  `invalidation_id` varchar(64) NOT NULL COMMENT '失效请求ID（事件幂等键）',
  `principal_id` varchar(64) NOT NULL COMMENT '安全主体ID',
  `hsm_uid` varchar(128) NOT NULL COMMENT '归一化HSM UID',
  `vin` varchar(32) DEFAULT NULL COMMENT '车辆VIN',
  `device_sn` varchar(64) DEFAULT NULL COMMENT '设备序列号',
  `invalidation_type` varchar(32) NOT NULL COMMENT 'CONNECTION_DISPOSAL / PRINCIPAL_REVOCATION',
  `reason` varchar(32) NOT NULL COMMENT 'BLOCK/RETIRE/REVOKE/UNBIND/REPLACEMENT/CONNECTION_DISPOSAL',
  `scope` varchar(32) NOT NULL COMMENT 'PRINCIPAL/CREDENTIAL/BINDING/SESSION',
  `security_version` bigint NOT NULL COMMENT '触发时安全状态版本（单调递增）',
  `binding_version` bigint DEFAULT NULL COMMENT '绑定版本（换件/解绑时）',
  `target_generation` bigint DEFAULT NULL COMMENT '目标会话generation（仅CONNECTION_DISPOSAL；不得误断更新会话）',
  `effective_at` datetime NOT NULL COMMENT '生效起点F（安全状态事务提交时间）',
  `effective_by` datetime NOT NULL COMMENT '生效时限（F+effective-by-seconds；当前开发目标30s，非已验证生产SLA）',
  `status` varchar(32) NOT NULL COMMENT 'PENDING/ACKNOWLEDGED/TIMEOUT/RECONCILED/CANCELLED_STALE',
  `receipt_state` varchar(32) DEFAULT NULL COMMENT '回执状态：CACHE_ACL_INVALIDATED/DISCONNECTED/SESSION_NOT_FOUND/FAILED_RETRY/ACCEPTED',
  `receipt_detail` varchar(512) DEFAULT NULL COMMENT '回执明细（VAGW执行证据摘要）',
  `execution_result_json` text DEFAULT NULL COMMENT '执行结果扩展（非敏感）',
  `event_payload_digest` varchar(64) DEFAULT NULL COMMENT '事件payload摘要（幂等/一致性）',
  `retry_count` int DEFAULT '0' COMMENT '重试次数',
  `last_retry_at` datetime DEFAULT NULL COMMENT '最近重试时间',
  `timeout_alerted` tinyint DEFAULT '0' COMMENT '是否已触发超时告警',
  `create_time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `create_by` varchar(64) DEFAULT NULL COMMENT '创建者',
  `modify_time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '修改时间',
  `modify_by` varchar(64) DEFAULT NULL COMMENT '修改者',
  `row_version` int DEFAULT '1' COMMENT '记录版本（乐观锁）',
  `row_valid` tinyint DEFAULT '1' COMMENT '记录是否有效',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_invalidation_id` (`invalidation_id`),
  KEY `idx_principal_status` (`principal_id`, `status`),
  KEY `idx_effective_by_status` (`effective_by`, `status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='访问失效执行跟踪表（回执/重试/超时/对账）';

-- ================= 安全操作审计（不可篡改操作事实） =================
CREATE TABLE IF NOT EXISTS `tb_viam_security_operation_audit` (
  `id` bigint NOT NULL AUTO_INCREMENT COMMENT '主键',
  `operation_id` varchar(64) NOT NULL COMMENT '操作ID（幂等键）',
  `principal_id` varchar(64) NOT NULL COMMENT '安全主体ID',
  `hsm_uid` varchar(128) DEFAULT NULL COMMENT '归一化HSM UID',
  `vin` varchar(32) DEFAULT NULL COMMENT '车辆VIN',
  `device_sn` varchar(64) DEFAULT NULL COMMENT '设备序列号',
  `operation` varchar(32) NOT NULL COMMENT 'BLOCK/UNBLOCK/RETIRE/REVOKE/UNBIND/REPLACEMENT/ROTATE/CLEAR_BLOCKING/ACCESS_INVALIDATION',
  `security_version` bigint NOT NULL COMMENT '操作后安全状态版本',
  `reason` varchar(128) DEFAULT NULL COMMENT '操作原因/说明',
  `detail` varchar(512) DEFAULT NULL COMMENT '操作详情（非敏感）',
  `operator_id` varchar(64) DEFAULT NULL COMMENT '真实操作人（EIAM用户ID或受信workload）',
  `operator_name` varchar(128) DEFAULT NULL COMMENT '操作人名称',
  `caller_type` varchar(32) DEFAULT NULL COMMENT 'MPT_ADMIN/VAGW/OAPI_MES',
  `occurred_at` datetime NOT NULL COMMENT '操作发生时间（安全状态提交时间）',
  `create_time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `create_by` varchar(64) DEFAULT NULL COMMENT '创建者',
  `modify_time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '修改时间',
  `modify_by` varchar(64) DEFAULT NULL COMMENT '修改者',
  `row_version` int DEFAULT '1' COMMENT '记录版本（乐观锁）',
  `row_valid` tinyint DEFAULT '1' COMMENT '记录是否有效',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_operation_id` (`operation_id`),
  KEY `idx_principal_occurred` (`principal_id`, `occurred_at`),
  KEY `idx_operation_occurred` (`operation`, `occurred_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='安全操作审计表（block/unblock/retire/revoke/unbind等）';
