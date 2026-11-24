package net.hwyz.iov.cloud.sec.viam.service.common.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 操作审计ID长度与唯一性测试（SEC-VIAM-DSN-CR-006 修复：operation_id 溢出）
 * <p>
 * 线上缺陷：`requestId:action:epochMilli` 拼接达 70 字符，超过
 * `tb_viam_certificate_operation.operation_id varchar(64)`。
 * </p>
 *
 * @author hwyz_leo
 */
@DisplayName("操作审计ID生成")
class ViamUtilsOperationIdTest {

    private static final String LONG_REQUEST_ID = "MPT-CERT-807a4c6f-d174-47d4-8937-1375e693d690"; // 45

    @Test
    @DisplayName("超长 requestId + 长 action：结果不超过 64 字符")
    void shouldNotExceedColumnWidth() {
        String id = ViamUtils.operationId("COMPENSATE", LONG_REQUEST_ID, 1795499999999L);
        assertTrue(id.length() <= 64, "len=" + id.length());
        assertTrue(id.startsWith("COMPENSATE:"));
    }

    @Test
    @DisplayName("同 scope/key/millis 恒定（幂等），不同 millis 不同（可追溯）")
    void shouldBeStableAndUnique() {
        String a = ViamUtils.operationId("COMPENSATE", LONG_REQUEST_ID, 1000L);
        String b = ViamUtils.operationId("COMPENSATE", LONG_REQUEST_ID, 1000L);
        String c = ViamUtils.operationId("COMPENSATE", LONG_REQUEST_ID, 1001L);
        assertEquals(a, b);
        assertNotEquals(a, c);
    }

    @Test
    @DisplayName("不同 requestId 同毫秒不碰撞")
    void shouldDifferByKey() {
        String a = ViamUtils.operationId("COMPENSATE", "REQ-A", 1000L);
        String b = ViamUtils.operationId("COMPENSATE", "REQ-B", 1000L);
        assertNotEquals(a, b);
    }

    @Test
    @DisplayName("极长 eventId（64 位派生键）+ 短 scope 仍不超宽")
    void shouldHandleLongEventId() {
        String eventId = "a".repeat(64);
        String id = ViamUtils.operationId("BFE", eventId, 1795499999999L);
        assertTrue(id.length() <= 64, "len=" + id.length());
    }

    @Test
    @DisplayName("超长 scope 截断至 16 字符")
    void shouldTruncateScope() {
        String id = ViamUtils.operationId("CONFIRM_INSTALLED_EXTREMELY_LONG", "REQ", 1000L);
        assertTrue(id.length() <= 64);
        assertEquals("CONFIRM_INSTALLE", id.substring(0, 16));
    }
}
