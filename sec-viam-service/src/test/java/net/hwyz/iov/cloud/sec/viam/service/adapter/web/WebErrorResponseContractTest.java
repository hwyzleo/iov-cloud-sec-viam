package net.hwyz.iov.cloud.sec.viam.service.adapter.web;

import net.hwyz.iov.cloud.framework.web.handler.GlobalExceptionHandler;
import net.hwyz.iov.cloud.framework.web.handler.ValidationExceptionHandler;
import net.hwyz.iov.cloud.framework.web.handler.WebRequestExceptionHandler;
import net.hwyz.iov.cloud.sec.viam.api.constant.ViamErrorCode;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateApplyVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.CertificateCompensateVo;
import net.hwyz.iov.cloud.sec.viam.api.vo.DeviceProofVerifyRequestVo;
import net.hwyz.iov.cloud.sec.viam.service.adapter.web.controller.mpt.MptViamCertificateController;
import net.hwyz.iov.cloud.sec.viam.service.adapter.web.controller.mpt.SecurityOperatorContext;
import net.hwyz.iov.cloud.sec.viam.service.adapter.web.controller.service.ServiceDeviceProofController;
import net.hwyz.iov.cloud.sec.viam.service.adapter.web.controller.service.ServiceVehicleCertificateController;
import net.hwyz.iov.cloud.sec.viam.service.application.service.CertificateProvisioningAppService;
import net.hwyz.iov.cloud.sec.viam.service.application.service.DeviceProofVerifyAppService;
import net.hwyz.iov.cloud.sec.viam.service.common.exception.ViamServiceException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * VIAM 错误响应契约测试（SEC-VIAM-DSN-CR-005）。
 * <p>
 * 锁定框架统一异常出口在 VIAM 两类端点上的行为：
 * </p>
 * <ul>
 *   <li>管理面（MPT，声明返回 {@code ApiResponse}）：业务错误 HTTP 200 + 702xxx + 可展示文案；</li>
 *   <li>机器面（Feign 官方服务，声明返回裸 VO/{@code void}）：业务错误非 2xx + 同一错误体，
 *       调用方不会把错误体反序列化成空数据而误判成功。</li>
 * </ul>
 *
 * @author hwyz_leo
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("SEC-VIAM-DSN-CR-005 错误响应契约")
class WebErrorResponseContractTest {

    private static final String COMPENSATE_URI = "/api/mpt/viam/certificate/compensate";
    private static final String APPLY_URI = "/api/service/vehicleCertificate/v1/apply";
    private static final String DEVICE_PROOF_URI = "/api/service/deviceProof/v1/verify";

    @Mock
    private CertificateProvisioningAppService certificateProvisioningAppService;
    @Mock
    private DeviceProofVerifyAppService deviceProofVerifyAppService;
    @Mock
    private SecurityOperatorContext securityOperatorContext;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders
                .standaloneSetup(
                        new MptViamCertificateController(certificateProvisioningAppService, securityOperatorContext),
                        new ServiceVehicleCertificateController(certificateProvisioningAppService),
                        new ServiceDeviceProofController(deviceProofVerifyAppService))
                .setControllerAdvice(new ValidationExceptionHandler(),
                        new WebRequestExceptionHandler(),
                        new GlobalExceptionHandler())
                .build();
    }

    @Test
    @DisplayName("MPT 补申请 702202：HTTP 200 + 业务码 + 可展示文案（原缺陷回归）")
    void mptCompensateReturnsBusinessCode() throws Exception {
        when(securityOperatorContext.operatorId()).thenReturn("99");
        when(certificateProvisioningAppService.compensate(any(CertificateCompensateVo.class),
                anyString(), any(), any(), any()))
                .thenThrow(new ViamServiceException(ViamErrorCode.CERTIFICATE_DEVICE_NOT_BOUND,
                        "请求VIN与ACTIVE资产映射不一致"));

        mockMvc.perform(post(COMPENSATE_URI)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(compensateBody()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value("702202"))
                .andExpect(jsonPath("$.message").value("请求VIN与ACTIVE资产映射不一致"));
    }

    @Test
    @DisplayName("MPT 补申请 702202：无 detail 时返回错误码登记文案")
    void mptCompensateReturnsRegisteredMessage() throws Exception {
        when(securityOperatorContext.operatorId()).thenReturn("99");
        when(certificateProvisioningAppService.compensate(any(CertificateCompensateVo.class),
                anyString(), any(), any(), any()))
                .thenThrow(new ViamServiceException(ViamErrorCode.CERTIFICATE_DEVICE_NOT_BOUND));

        mockMvc.perform(post(COMPENSATE_URI)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(compensateBody()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value("702202"))
                .andExpect(jsonPath("$.message").value("设备与车辆未建立active绑定"));
    }

    @Test
    @DisplayName("MPT 未预期异常：HTTP 500 + 100002，不暴露内部细节")
    void mptUnexpectedException() throws Exception {
        when(securityOperatorContext.operatorId()).thenReturn("99");
        when(certificateProvisioningAppService.compensate(any(CertificateCompensateVo.class),
                anyString(), any(), any(), any()))
                .thenThrow(new IllegalStateException("pki down"));

        mockMvc.perform(post(COMPENSATE_URI)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(compensateBody()))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.code").value("100002"))
                .andExpect(jsonPath("$.message").value("系统内部错误"));
    }

    @Test
    @DisplayName("机器面证书申请 702201：HTTP 422 + 业务码（不得 200）")
    void serviceApplyReturnsNon2xx() throws Exception {
        when(certificateProvisioningAppService.apply(any(CertificateApplyVo.class)))
                .thenThrow(new ViamServiceException(ViamErrorCode.CERTIFICATE_VIN_NOT_EXIST));

        mockMvc.perform(post(APPLY_URI)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(applyBody()))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.code").value("702201"));
    }

    @Test
    @DisplayName("机器面设备证明 702720：HTTP 400 + 业务码（调用方按请求不合法处理）")
    void serviceDeviceProofParamInvalid() throws Exception {
        when(deviceProofVerifyAppService.verify(any(DeviceProofVerifyRequestVo.class), anyString()))
                .thenThrow(new ViamServiceException(ViamErrorCode.PROOF_VERIFY_PARAM_INVALID,
                        "不支持的证明类型: UNKNOWN"));

        mockMvc.perform(post(DEVICE_PROOF_URI)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(deviceProofBody()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("702720"))
                .andExpect(jsonPath("$.message").value("不支持的证明类型: UNKNOWN"));
    }

    @Test
    @DisplayName("机器面入参校验失败：HTTP 400 + 100001")
    void serviceDeviceProofBeanValidation() throws Exception {
        mockMvc.perform(post(DEVICE_PROOF_URI)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("100001"));
    }

    private static String compensateBody() {
        return """
                {
                  "vin": "VIN-1",
                  "deviceCategory": "TBOX",
                  "deviceSn": "SN-1",
                  "certificateProfile": "TBOX_TSP_CLIENT",
                  "csrDerBase64": "MIIB",
                  "ticketNo": "T-1",
                  "reason": "MES未达"
                }
                """;
    }

    private static String applyBody() {
        return """
                {
                  "requestId": "MES-1",
                  "vin": "VIN-1",
                  "deviceCategory": "TBOX",
                  "deviceSn": "SN-1",
                  "certificateProfile": "TBOX_TSP_CLIENT",
                  "csrDerBase64": "MIIB"
                }
                """;
    }

    private static String deviceProofBody() {
        return """
                {
                  "proofType": "UNKNOWN",
                  "proof": "AAAA",
                  "nonce": "0123456789abcdef"
                }
                """;
    }
}
