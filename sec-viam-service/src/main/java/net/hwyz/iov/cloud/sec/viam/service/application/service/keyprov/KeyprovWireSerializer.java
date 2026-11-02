package net.hwyz.iov.cloud.sec.viam.service.application.service.keyprov;

import com.google.protobuf.CodedOutputStream;
import com.google.protobuf.MessageLite;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Keyprov canonical wire 确定性序列化（KL1 field4 patch 与重放字节稳定性的前提）。
 *
 * @author hwyz_leo
 */
public final class KeyprovWireSerializer {

    private KeyprovWireSerializer() {
    }

    /**
     * 确定性序列化（map 排序稳定、字段号顺序固定）。
     */
    public static byte[] serialize(MessageLite message) {
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream(message.getSerializedSize());
            CodedOutputStream output = CodedOutputStream.newInstance(buffer);
            output.useDeterministicSerialization();
            message.writeTo(output);
            output.flush();
            return buffer.toByteArray();
        } catch (IOException e) {
            throw new KeyprovEnvelopeException("canonical wire 确定性序列化失败", e);
        }
    }
}
