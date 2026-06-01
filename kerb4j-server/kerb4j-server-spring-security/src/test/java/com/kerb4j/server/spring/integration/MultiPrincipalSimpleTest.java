package com.kerb4j.server.spring.integration;

import com.kerb4j.client.SpnegoClient;
import com.kerb4j.server.MultiPrincipalManager;
import com.kerb4j.server.spring.jaas.sun.SunJaasKerberosTicketValidator;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.FileSystemResource;

import java.io.File;
import java.io.IOException;
import java.util.Collection;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class MultiPrincipalSimpleTest {

    @Test
    void pureMultiPrincipalModeRequiresConfiguredPrincipals() {
        SunJaasKerberosTicketValidator validator = new SunJaasKerberosTicketValidator();
        validator.setMultiPrincipalManager(new StubMultiPrincipalManager(List.of(), null));
        assertThrows(IllegalStateException.class, validator::afterPropertiesSet);
    }

    @Test
    void pureMultiPrincipalModeInitializesWithoutSinglePrincipalConfiguration() {
        SunJaasKerberosTicketValidator validator = new SunJaasKerberosTicketValidator();
        validator.setMultiPrincipalManager(new StubMultiPrincipalManager(
                List.of("HTTP/server.example.com@EXAMPLE.COM"),
                null));
        assertDoesNotThrow(validator::afterPropertiesSet);
    }

    @Test
    void singlePrincipalModeRemainsBackwardCompatible() throws IOException {
        File keytab = File.createTempFile("single", ".keytab");
        keytab.deleteOnExit();

        SunJaasKerberosTicketValidator validator = new SunJaasKerberosTicketValidator();
        validator.setServicePrincipal("HTTP/server.example.com@EXAMPLE.COM");
        validator.setKeyTabLocation(new FileSystemResource(keytab));

        assertDoesNotThrow(validator::afterPropertiesSet);
    }

    @NullMarked
    private static final class StubMultiPrincipalManager implements MultiPrincipalManager {
        private final Collection<String> configuredSpns;
        private final @Nullable SpnegoClient fallbackClient;

        private StubMultiPrincipalManager(Collection<String> configuredSpns,
                                          @Nullable SpnegoClient fallbackClient) {
            this.configuredSpns = configuredSpns;
            this.fallbackClient = fallbackClient;
        }

        @Override
        public @Nullable SpnegoClient getSpnegoClientForSpn(@Nullable String spn) {
            return fallbackClient;
        }

        @Override
        public boolean hasPrincipalForSpn(String spn) {
            return configuredSpns.contains(spn);
        }

        @Override
        public Collection<String> getConfiguredSpns() {
            return configuredSpns;
        }

        @Override
        public @Nullable SpnegoClient getDefaultSpnegoClient() {
            return fallbackClient;
        }
    }
}
