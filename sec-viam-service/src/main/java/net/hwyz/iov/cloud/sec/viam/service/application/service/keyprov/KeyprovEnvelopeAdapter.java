package net.hwyz.iov.cloud.sec.viam.service.application.service.keyprov;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.hwyz.iov.cloud.framework.security.crypto.model.DerivedWrappedKey;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.DeviceBusinessKey;
import net.hwyz.iov.security.keyprov.v1.KeyEnvelopeFormat;
import net.hwyz.iov.security.keyprov.v1.KeyProvisioningRequest;
import net.hwyz.iov.security.keyprov.v1.WrappedKeyItem;
import net.hwyz.iov.security.keyprov.v1.WrappingSuite;
import org.springframework.stereotype.Component;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Keyprov 协议 Adapter：Request envelope 能力协商 + 委托 PAR-PROTO Wire Mapper 组装 Response item
 * （迁入 VMD 既有实现）。
 *
 * @author hwyz_leo
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class KeyprovEnvelopeAdapter {

    private final ParProtoWireMapperV1 wireMapper;

    /**
     * Request envelope v1 能力协商（fail-closed）。
     */
    public KeyEnvelopeFormat negotiateEnvelopeFormat(KeyProvisioningRequest request) {
        if (request == null) {
            return null;
        }
        Set<KeyEnvelopeFormat> formats = new LinkedHashSet<>();
        for (KeyEnvelopeFormat format : request.getSupportedEnvelopeFormatsList()) {
            if (format == null || format == KeyEnvelopeFormat.UNRECOGNIZED
                    || format == KeyEnvelopeFormat.KEY_ENVELOPE_FORMAT_UNSPECIFIED) {
                return null;
            }
            formats.add(format);
        }
        if (!formats.contains(KeyEnvelopeFormat.KEY_ENVELOPE_FORMAT_ECDH_ES_P256_V1)) {
            return null;
        }
        boolean ecdhDeclared = request.getSupportedWrappingSuitesList().stream()
                .anyMatch(suite -> suite == WrappingSuite.WRAPPING_SUITE_ECDH_ES_P256_HKDF_SHA256_AES256GCM);
        if (!ecdhDeclared) {
            return null;
        }
        return KeyEnvelopeFormat.KEY_ENVELOPE_FORMAT_ECDH_ES_P256_V1;
    }

    /**
     * 将派生封装结果映射为 canonical {@link WrappedKeyItem}（委托 PAR-PROTO Wire Mapper）。
     */
    public WrappedKeyItem toWrappedKeyItem(String requestId, String businessDomain, DeviceBusinessKey directory,
                                           DerivedWrappedKey source) {
        return wireMapper.map(source, new KeyProvisioningWireContext(requestId, businessDomain), directory).item();
    }
}
