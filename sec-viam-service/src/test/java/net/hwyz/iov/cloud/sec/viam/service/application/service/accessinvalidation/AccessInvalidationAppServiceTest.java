package net.hwyz.iov.cloud.sec.viam.service.application.service.accessinvalidation;

import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.AccessInvalidationRecord;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.DeviceOnboarding;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.PrincipalAssetMapping;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SecurityOperationAudit;
import net.hwyz.iov.cloud.sec.viam.service.domain.model.entity.SecurityPrincipal;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.AccessInvalidationRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.DeviceOnboardingRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.PrincipalAssetMappingRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.SecurityOperationAuditRepository;
import net.hwyz.iov.cloud.sec.viam.service.domain.repository.SecurityPrincipalRepository;
import net.hwyz.iov.cloud.sec.viam.service.infrastructure.outbox.ViamOutboxWriter;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * 访问失效应用服务测试（SEC-VIAM-DSN-CR-001 / FR-VIAM-008 / T05 / G-3）
 *
 * @author hwyz_leo
 */
@ExtendWith(MockitoExtension.class)
class AccessInvalidationAppServiceTest {

    @Mock
    private ViamOutboxWriter outboxWriter;

    private final InMemPrincipalRepo principalRepo = new InMemPrincipalRepo();
    private final InMemOnboardingRepo onboardingRepo = new InMemOnboardingRepo();
    private final InMemMappingRepo mappingRepo = new InMemMappingRepo();
    private final InMemInvalidationRepo invalidationRepo = new InMemInvalidationRepo();
    private final InMemAuditRepo auditRepo = new InMemAuditRepo();
    private AccessInvalidationAppService appService;

    @BeforeEach
    void setUp() {
        appService = new AccessInvalidationAppService(
                principalRepo, mappingRepo, onboardingRepo, invalidationRepo, auditRepo,
                outboxWriter, new ObjectMapper().findAndRegisterModules());
    }

    private void seedActive(String principalId) {
        principalRepo.save(SecurityPrincipal.builder()
                .principalId(principalId).hsmUid("HSM-1")
                .state(SecurityPrincipal.PrincipalState.ACTIVE).build());
        onboardingRepo.save(DeviceOnboarding.builder()
                .principalId(principalId).hsmUid("HSM-1").vin("VHN00000000000001").deviceSn("SN-1")
                .state(DeviceOnboarding.OnboardingState.ACTIVE)
                .firstLoginTime(Instant.now().minusSeconds(3600))
                .lastLoginTime(Instant.now().minusSeconds(3600))
                .build());
        mappingRepo.save(PrincipalAssetMapping.builder()
                .principalId(principalId).vin("VHN00000000000001").deviceSn("SN-1").bindingVersion(1L)
                .state(PrincipalAssetMapping.MappingState.ACTIVE).build());
    }

    @Test
    void blockIncrementsVersionPublishesEventAndAudits() {
        seedActive("PR-1");
        appService.block("PR-1", "违规设备", "op-1", "MPT_ADMIN");

        DeviceOnboarding onboarding = onboardingRepo.byId.get("PR-1");
        assertEquals(DeviceOnboarding.OnboardingState.BLOCKED, onboarding.getState());
        assertEquals(1, onboarding.getSecurityVersion());
        assertEquals(SecurityPrincipal.PrincipalState.BLOCKED, principalRepo.byId.get("PR-1").getState());
        SecurityOperationAudit audit = auditRepo.byId.get("PR-1");
        assertNotNull(audit);
        assertEquals("BLOCK", audit.getOperation());
        assertEquals("op-1", audit.getOperatorId());
        AccessInvalidationRecord record = invalidationRepo.byId.get("PR-1");
        assertNotNull(record);
        assertEquals(AccessInvalidationRecord.STATUS_PENDING, record.getStatus());
        assertNotNull(record.getEffectiveBy());
        assertTrue(record.getEffectiveBy().isAfter(record.getEffectiveAt()));
        verify(outboxWriter).enqueue(any(), any(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void unblockRestoresReauthEligibilityNotOldAcl() {
        seedActive("PR-2");
        appService.block("PR-2", "临时封禁", "op-1", "MPT_ADMIN");
        appService.unblock("PR-2", "op-2", "MPT_ADMIN");

        DeviceOnboarding onboarding = onboardingRepo.byId.get("PR-2");
        assertEquals(DeviceOnboarding.OnboardingState.ACTIVATING, onboarding.getState());
        assertEquals(2, onboarding.getSecurityVersion());
        assertEquals(SecurityPrincipal.PrincipalState.ACTIVE, principalRepo.byId.get("PR-2").getState());
        // 仅 block 发布一次失效事件；unblock 不发布（仅恢复重新认证资格）
        verify(outboxWriter, times(1)).enqueue(any(), any(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void retireTerminalAndPublishes() {
        seedActive("PR-3");
        appService.retire("PR-3", "设备报废", "op-1", "MPT_ADMIN");
        DeviceOnboarding onboarding = onboardingRepo.byId.get("PR-3");
        assertEquals(DeviceOnboarding.OnboardingState.RETIRED, onboarding.getState());
        assertEquals(1, onboarding.getSecurityVersion());
        assertEquals(AccessInvalidationRecord.STATUS_PENDING, invalidationRepo.byId.get("PR-3").getStatus());
    }

    // ================= 独立内存仓储 =================

    static class InMemPrincipalRepo implements SecurityPrincipalRepository {
        final Map<String, SecurityPrincipal> byId = new HashMap<>();

        @Override
        public Optional<SecurityPrincipal> findByPrincipalId(String principalId) {
            return Optional.ofNullable(byId.get(principalId));
        }

        @Override
        public Optional<SecurityPrincipal> findByHsmUid(String hsmUid) {
            return byId.values().stream().filter(p -> hsmUid.equals(p.getHsmUid())).findFirst();
        }

        @Override
        public void save(SecurityPrincipal principal) {
            byId.put(principal.getPrincipalId(), principal);
        }

        @Override
        public List<SecurityPrincipal> listAll(int offset, int limit) {
            return new ArrayList<>(byId.values());
        }
    }

    static class InMemOnboardingRepo implements DeviceOnboardingRepository {
        final Map<String, DeviceOnboarding> byId = new HashMap<>();

        @Override
        public Optional<DeviceOnboarding> findByPrincipalId(String principalId) {
            return Optional.ofNullable(byId.get(principalId));
        }

        @Override
        public void save(DeviceOnboarding onboarding) {
            byId.put(onboarding.getPrincipalId(), onboarding);
        }
    }

    static class InMemMappingRepo implements PrincipalAssetMappingRepository {
        final Map<String, PrincipalAssetMapping> byId = new HashMap<>();

        @Override
        public Optional<PrincipalAssetMapping> findByPrincipalAndVin(String principalId, String vin) {
            return byId.values().stream()
                    .filter(m -> principalId.equals(m.getPrincipalId()) && vin.equals(m.getVin())
                            && m.getState() == PrincipalAssetMapping.MappingState.ACTIVE).findFirst();
        }

        @Override
        public List<PrincipalAssetMapping> listActiveByPrincipalId(String principalId) {
            return byId.values().stream()
                    .filter(m -> principalId.equals(m.getPrincipalId())
                            && m.getState() == PrincipalAssetMapping.MappingState.ACTIVE).toList();
        }

        @Override
        public List<PrincipalAssetMapping> listActiveByVin(String vin) {
            return byId.values().stream()
                    .filter(m -> vin.equals(m.getVin())
                            && m.getState() == PrincipalAssetMapping.MappingState.ACTIVE).toList();
        }

        @Override
        public Optional<PrincipalAssetMapping> findActiveByDeviceSn(String deviceSn) {
            return byId.values().stream()
                    .filter(m -> deviceSn.equals(m.getDeviceSn())
                            && m.getState() == PrincipalAssetMapping.MappingState.ACTIVE).findFirst();
        }

        @Override
        public void save(PrincipalAssetMapping mapping) {
            byId.put(mapping.getPrincipalId(), mapping);
        }
    }

    static class InMemInvalidationRepo implements AccessInvalidationRepository {
        final Map<String, AccessInvalidationRecord> byId = new HashMap<>();

        @Override
        public Optional<AccessInvalidationRecord> findByInvalidationId(String invalidationId) {
            return byId.values().stream()
                    .filter(r -> invalidationId.equals(r.getInvalidationId())).findFirst();
        }

        @Override
        public List<AccessInvalidationRecord> listPendingBefore(Instant now, int limit) {
            return List.of();
        }

        @Override
        public void save(AccessInvalidationRecord record) {
            byId.put(record.getPrincipalId(), record);
        }
    }

    static class InMemAuditRepo implements SecurityOperationAuditRepository {
        final Map<String, SecurityOperationAudit> byId = new HashMap<>();

        @Override
        public Optional<SecurityOperationAudit> findByOperationId(String operationId) {
            return Optional.empty();
        }

        @Override
        public void save(SecurityOperationAudit audit) {
            byId.put(audit.getPrincipalId(), audit);
        }
    }
}
