package net.hwyz.iov.cloud.sec.viam.service.domain.model.query;

import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.CredentialEnrollment;

import java.util.List;

/**
 * 证书申请分页查询结果（SEC-VIAM-DSN-CR-002 / D-VIAM-012）
 * <p>
 * 领域层只回传条目与总数，不暴露 PageHelper 的 Page 类型，
 * 由适配层组装 framework {@code PageResult}。
 * </p>
 *
 * @param items 当前页条目
 * @param total 满足条件的总记录数
 * @author hwyz_leo
 */
public record CertificatePage(List<CredentialEnrollment> items, long total) {
}
