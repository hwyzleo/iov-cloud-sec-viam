package net.hwyz.iov.cloud.sec.viam.api.constant;

import lombok.AllArgsConstructor;
import lombok.Getter;
import net.hwyz.iov.cloud.framework.common.exception.ErrorCode;

/**
 * VIAM 服务错误码注册表（SEC-VIAM-DSN-CR-001 §3）
 * <p>
 * 新码统一使用 {@code 702xxx} 命名空间，与旧 806xxx（VMD）/ 401xxx（TSP）源码的映射
 * 在单一分类层 {@link ViamLegacyCodeMapping} 维护；VAGW 继续输出自身 804xxx。
 * 旧错误号退役不复用。
 * </p>
 * <ul>
 *   <li>702001～702099：安全主体 / 身份关联 / 资产映射</li>
 *   <li>702100～702199：准入裁决 / 成功接入证据 / 登录时间线</li>
 *   <li>702200～702299：设备证书生命周期</li>
 *   <li>702300～702399：业务密钥目录</li>
 *   <li>702400～702499：Keyprov 开通批次 / ACK / 租约</li>
 *   <li>702500～702599：安全开通状态机（onboarding）</li>
 *   <li>702600～702699：审计 / 事件 / 幂等 / 对账</li>
 * </ul>
 *
 * @author hwyz_leo
 */
@Getter
@AllArgsConstructor
public enum ViamErrorCode implements ErrorCode {

    // ================= 安全主体 / 身份关联（702001～702099） =================
    PRINCIPAL_NOT_EXIST("702001", "安全主体不存在"),
    PRINCIPAL_UID_UNAVAILABLE("702002", "设备HSM UID缺失或来源冲突，无法建立安全主体"),
    PRINCIPAL_ASSET_MAPPING_CONFLICT("702003", "安全主体资产映射冲突（同一VIN/设备存在多条有效映射）"),
    PRINCIPAL_ASSET_MAPPING_NOT_EXIST("702004", "安全主体资产映射不存在"),
    PRINCIPAL_REGISTRATION_NOT_TRUSTED("702005", "安全主体登记来源不可信，拒绝登记"),
    PRINCIPAL_UID_SELF_REPORTED_REJECTED("702006", "客户端自报UID不可作为身份关联依据，拒绝仅凭自报建立映射"),

    // ================= 准入裁决 / 成功接入（702100～702199） =================
    ADMISSION_UID_UNKNOWN("702101", "设备接入身份未知（UID在受信事实中不存在）"),
    ADMISSION_IDENTITY_MISMATCH("702102", "证书CN与请求身份不一致，拒绝接入"),
    ADMISSION_UNBOUND("702103", "设备无当前有效绑定，拒绝接入"),
    ADMISSION_BINDING_CONFLICT("702104", "设备存在多条ACTIVE绑定，fail-closed"),
    ADMISSION_CERT_REVOKED("702105", "设备证书已被吊销"),
    ADMISSION_CERT_EXPIRED("702106", "设备证书已过期"),
    ADMISSION_DEVICE_BLOCKED("702107", "设备已安全封禁"),
    ADMISSION_DEVICE_RETIRED("702108", "设备已退役"),
    ADMISSION_DEPENDENCY_UNAVAILABLE("702109", "准入依赖（PKI/受信事实）不可用或结果不确定，fail-closed"),
    ADMISSION_LEAF_CERT_INVALID("702110", "本次mTLS叶子证书无效或证据不完整"),
    LOGIN_EVIDENCE_NOT_TRUSTED("702111", "成功接入事件缺少可信关联证据（admissionDecisionId/不可变准入快照或等效绑定证据）"),
    LOGIN_EVIDENCE_STALE_GENERATION("702112", "成功接入事件generation过期或身份不一致，拒绝写入"),
    LOGIN_RECORD_NOT_EXIST("702113", "成功接入记录不存在"),

    // ================= 设备证书生命周期（702200～702299） =================
    CERTIFICATE_VIN_NOT_EXIST("702201", "VIN不存在或状态不允许申请证书"),
    CERTIFICATE_DEVICE_NOT_BOUND("702202", "设备与车辆未建立active绑定"),
    CERTIFICATE_DEVICE_CATEGORY_MISMATCH("702203", "设备类别不匹配"),
    CERTIFICATE_CSR_INVALID("702204", "CSR格式或签名无效"),
    CERTIFICATE_CSR_SUBJECT_MISMATCH("702205", "CSR Subject CN缺失、重复或与hsm_uid/ecu_uid不一致"),
    CERTIFICATE_CSR_CONTAINS_VIN("702206", "CSR不应包含VIN"),
    CERTIFICATE_PROFILE_NOT_ALLOWED("702207", "证书Profile不允许"),
    CERTIFICATE_PKI_UNAVAILABLE("702208", "PKI服务不可用"),
    CERTIFICATE_ISSUANCE_UNKNOWN("702209", "签发结果未知，待对账"),
    CERTIFICATE_PKI_REJECTED("702210", "PKI明确拒签"),
    CERTIFICATE_INSTALL_CONFIRM_MISMATCH("702211", "证书安装确认对象不匹配"),
    CERTIFICATE_STATUS_NOT_ALLOWED("702212", "证书状态不允许此操作"),
    CERTIFICATE_REQUEST_NOT_EXIST("702213", "证书申请不存在"),
    CERTIFICATE_COMPENSATION_NOT_ALLOWED("702214", "当前证书申请状态不允许补偿"),
    CERTIFICATE_REQUEST_IDEMPOTENCY_CONFLICT("702215", "证书申请幂等键冲突"),
    CERTIFICATE_KEY_CONFLICT("702216", "同设备身份已存在不同公钥的有效/处理中证书，需授权换钥"),
    CERTIFICATE_ISSUED_PROFILE_MISMATCH("702217", "签发后复验Profile不匹配，确定性拒绝"),
    CERTIFICATE_UID_BINDING_MISMATCH("702218", "签发后复验UID绑定不匹配，确定性拒绝"),
    CERTIFICATE_PUBLIC_KEY_BINDING_MISMATCH("702219", "签发后复验公钥绑定不匹配，确定性拒绝"),
    CERTIFICATE_MATERIAL_UNAVAILABLE("702220", "证书材料或依赖暂不可用（非确定性拒绝，保持ISSUING）"),

    // ================= 业务密钥目录（702300～702399） =================
    BUSINESS_KEY_DEVICE_SESSION_MISMATCH("702301", "设备会话身份与请求deviceSn不一致"),
    BUSINESS_KEY_DOMAIN_NOT_AUTHORIZED("702302", "业务域或用途未授权"),
    BUSINESS_KEY_NOT_EXIST("702303", "业务密钥不存在或当前无ACTIVE"),
    BUSINESS_KEY_MULTIPLE_ACTIVE("702304", "业务密钥目录存在多个ACTIVE，数据异常需对账"),
    BUSINESS_KEY_STATE_NOT_ALLOWED("702305", "业务密钥状态不允许此操作"),
    BUSINESS_KEY_IDEMPOTENCY_CONFLICT("702306", "业务密钥申请幂等键冲突"),
    BUSINESS_KEY_ROTATION_CONFLICT("702307", "业务密钥轮换并发冲突"),
    BUSINESS_KEY_DEVICE_CERT_NOT_FOUND("702308", "有效设备证书不存在"),
    BUSINESS_KEY_KMS_UNAVAILABLE("702309", "KMS/HSM或framework安全服务不可用"),
    BUSINESS_KEY_WRAP_FAILED("702310", "业务密钥设备封装失败"),
    BUSINESS_KEY_REVOCATION_FAILED("702311", "业务密钥吊销失败"),
    BUSINESS_KEY_OUTCOME_UNKNOWN("702312", "密钥操作结果未知，需以原幂等键对账"),
    BUSINESS_KEY_DERIVATION_REJECTED("702313", "根派生被拒绝（版本/代际校验不一致）"),
    BUSINESS_KEY_LOGICAL_IDENTITY_CONFLICT("702314", "逻辑材料身份冲突（同逻辑身份不同material属性）"),

    // ================= Keyprov 开通批次 / ACK / 租约（702400～702499） =================
    KEYPROV_REQUEST_INVALID("702401", "Keyprov请求协议校验失败（端点/payloadType/schemaVersion/digest）"),
    KEYPROV_ENVELOPE_INTEGRITY_FAILED("702402", "Keyprov信封完整性校验失败"),
    KEYPROV_PROVISIONING_NOT_FOUND("702403", "业务密钥开通批次不存在"),
    KEYPROV_PROVISIONING_PURPOSE_INCOMPLETE("702404", "业务密钥用途集合不完整或非法"),
    KEYPROV_ACK_CONFLICT("702405", "设备导入ACK摘要冲突，已记录安全告警"),
    KEYPROV_PROVISIONING_STATE_NOT_ALLOWED("702406", "业务密钥开通批次状态不允许此操作"),
    KEYPROV_ITEM_MISMATCH("702407", "设备导入ACK item与开通批次不匹配"),
    KEYPROV_DEVICE_NOT_ELIGIBLE("702408", "设备绑定或证书失效，不允许完成开通"),
    KEYPROV_PROVISIONING_EXPIRED("702409", "业务密钥开通批次已过期"),
    KEYPROV_ACK_DEADLINE_EXCEEDED("702410", "ACK超过固定截止时间（KL1 B），不再接受"),
    KEYPROV_LEASE_CONFLICT("702411", "交付租约冲突（同messageId不得对应不同bytes）"),
    KEYPROV_LEASE_NOT_ISSUABLE("702412", "租约不可签发（E-now&lt;20s，禁止签发）"),
    KEYPROV_TERMINAL_STATE_FROZEN("702413", "批次已进入终态，不得复活"),
    KEYPROV_PROVIDER_CALL_UNKNOWN("702414", "Provider调用结果未知，禁止自动重放，转对账"),
    KEYPROV_RESPONSE_FROZEN("702415", "响应已冻结（不可变内容摘要C），重放不得改变字节"),
    KEYPROV_IMPORT_PROOF_VERIFICATION_FAILED("702416", "设备导入证明验签失败（ImportProof，fail-closed）"),
    KEYPROV_ACK_TERMINAL_STATE("702417", "ACK到达终态批次：失败终态不复活；ACTIVE一致重复ACK幂等处理"),
    KEYPROV_IMPORT_FAILED("702418", "设备导入失败（ImportResult非IMPORTED）"),

    // ================= 安全开通状态机（702500～702599） =================
    ONBOARDING_NOT_EXIST("702501", "设备安全开通状态不存在"),
    ONBOARDING_STATE_NOT_ALLOWED("702502", "安全开通状态不允许此操作（终态不复活/不跨级激活）"),
    ONBOARDING_ACTIVATE_WITHOUT_ACK("702503", "完整用途集ACK未确认，禁止激活"),
    ONBOARDING_ACTIVATE_WITHOUT_LOGIN("702504", "无可信成功接入记录，禁止进入ACTIVATING"),
    ONBOARDING_RECONCILE_REQUIRED("702505", "跨Topic乱序或对账未完成，禁止跨级推进"),

    // ================= 审计 / 事件 / 幂等 / 对账（702600～702699） =================
    EVENT_UNIQUE_KEY_DUPLICATE("702601", "事件唯一键重复"),
    EVENT_CONTRACT_DIGEST_MISMATCH("702602", "事件契约摘要不一致"),
    IDEMPOTENCY_CONFLICT("702603", "幂等键冲突（同requestId不同请求摘要）"),
    OUTBOX_DEAD_LETTER("702604", "Outbox事件进入死信队列，需人工对账"),
    INBOX_DUPLICATE_EVENT("702605", "Inbox重复事件（已按原eventId去重）"),
    RECONCILE_NOT_ALLOWED("702606", "当前状态不允许对账操作"),
    OPERATION_NOT_FOUND("702607", "操作记录不存在"),
    CONFIGURATION_INVALID("702608", "VIAM安全配置无效（fail-closed）"),
    SECURITY_FACT_NOT_MODIFIABLE("702609", "安全事实不可人工修改（禁止改写登录时间/伪造成功）"),

    // ================= 服务身份 / workload（702700～702709） =================
    SERVICE_IDENTITY_MISSING("702700", "服务身份头缺失、为空或多值歧义，拒绝访问"),
    SERVICE_IDENTITY_FORBIDDEN("702701", "服务身份未知（X-Client-Id 未登记），拒绝访问"),
    SERVICE_IDENTITY_PERMISSION_DENIED("702705", "服务身份有效但无权访问该接口"),

    // ================= 访问失效 / 安全状态变更（702710～702719） =================
    PRINCIPAL_BLOCK_NOT_ALLOWED("702710", "安全主体状态不允许封禁"),
    PRINCIPAL_UNBLOCK_NOT_ALLOWED("702711", "安全主体状态不允许解除封禁"),
    PRINCIPAL_RETIRE_NOT_ALLOWED("702712", "安全主体状态不允许退役"),
    ACCESS_INVALIDATION_NOT_FOUND("702713", "访问失效执行记录不存在"),
    ACCESS_INVALIDATION_EXECUTION_TIMEOUT("702714", "访问失效执行超时（生效时限内未确认）"),
    ACCESS_INVALIDATION_RECEIPT_MISMATCH("702715", "访问失效执行回执与请求不一致"),
    ACCESS_INVALIDATION_STALE_VERSION("702716", "访问失效事件版本落后于当前安全状态（乱序旧事件，忽略不执行）");

    private final String code;
    private final String message;
}
