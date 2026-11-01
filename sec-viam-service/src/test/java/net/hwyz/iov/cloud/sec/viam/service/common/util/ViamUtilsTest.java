package net.hwyz.iov.cloud.sec.viam.service.application.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * VIAM 通用工具单元测试（SEC-VIAM-DSN-CR-001）
 *
 * @author hwyz_leo
 */
class ViamUtilsTest {

    @Test
    void normalizeUid_trimsAndUpperCases() {
        assertEquals("HSM-0001", net.hwyz.iov.cloud.sec.viam.service.common.util.ViamUtils.normalizeUid("  hsm-0001 "));
        assertNull(net.hwyz.iov.cloud.sec.viam.service.common.util.ViamUtils.normalizeUid("  "));
    }

    @Test
    void principalId_isStableAndDistinctFromHsmUid() {
        String id1 = net.hwyz.iov.cloud.sec.viam.service.common.util.ViamUtils.newPrincipalId("HSM-0001");
        String id2 = net.hwyz.iov.cloud.sec.viam.service.common.util.ViamUtils.newPrincipalId("hsm-0001");
        assertEquals(id1, id2); // 归一化后稳定
        assertNotEquals("HSM-0001", id1);
        assertNotNull(id1);
        org.junit.jupiter.api.Assertions.assertTrue(id1.startsWith("PR-"));
    }

    @Test
    void loginId_derivedFromUidAndGeneration() {
        String l1 = net.hwyz.iov.cloud.sec.viam.service.common.util.ViamUtils.newLoginId("HSM-0001", 1);
        String l2 = net.hwyz.iov.cloud.sec.viam.service.common.util.ViamUtils.newLoginId("HSM-0001", 1);
        String l3 = net.hwyz.iov.cloud.sec.viam.service.common.util.ViamUtils.newLoginId("HSM-0001", 2);
        assertEquals(l1, l2); // 同 uid+generation 幂等
        assertNotEquals(l1, l3); // 新 generation 新记录
    }

    @Test
    void canonicalCertSn_normalizesHex() {
        assertEquals("0a1b2c", net.hwyz.iov.cloud.sec.viam.service.common.util.ViamUtils.canonicalCertSn("0A:1B:2C"));
    }
}
