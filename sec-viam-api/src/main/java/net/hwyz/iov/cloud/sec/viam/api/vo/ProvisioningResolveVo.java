package net.hwyz.iov.cloud.sec.viam.api.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;

/**
 * 证书申请→开通批次桥接结果VO（SEC-VIAM-DSN-CR-002 / D-VIAM-017）
 * <p>
 * 证书申请 requestId（MPT-CERT-*）与开通批次 requestId（kp-*）是两套标识，
 * 本结构显式返回候选集，命中唯一时给出 selected，多命中不静默择一。
 * </p>
 *
 * @author hwyz_leo
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProvisioningResolveVo {

    /** 证书申请 requestId */
    private String certificateRequestId;

    /** 解析出的设备SN（来自证书申请记录） */
    private String deviceSn;

    /** 解析出的车辆VIN（来自证书申请记录） */
    private String vin;

    /** 业务域 */
    private String businessDomain;

    /** 候选批次（按发起时间倒序） */
    private List<Candidate> candidates;

    /** 唯一命中时的批次 requestId；多命中/无命中为空 */
    private String selected;

    /** 桥接结果：UNIQUE / MULTIPLE / NONE */
    private String resolution;

    /**
     * 候选批次摘要。
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Candidate {

        /** 批次 requestId */
        private String requestId;

        /** 批次状态 */
        private String status;

        /** 是否未终结（open_flag=1） */
        private Boolean open;

        /** 开始时间 */
        private Instant startedAt;

        /** 完成时间 */
        private Instant completedAt;
    }
}
