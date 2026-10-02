package com.kerb4j.server.spring.webflux;

import com.kerb4j.server.MultiPrincipalManager;
import com.kerb4j.server.spring.SimpleMultiPrincipalManager;
import com.kerb4j.server.spring.jaas.sun.SunJaasKerberosTicketValidator;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies that the multi-principal building blocks available to the reactive
 * (WebFlux) stack are the same shared-core classes used by the servlet stack.
 */
class MultiPrincipalParityTest {

    @Test
    void coreMultiPrincipalSupportIsAvailableForReactiveConfigurations() {
        SimpleMultiPrincipalManager manager = new SimpleMultiPrincipalManager();
        SunJaasKerberosTicketValidator validator = new SunJaasKerberosTicketValidator();

        assertThat(manager).isInstanceOf(MultiPrincipalManager.class);
        assertDoesNotThrow(() -> validator.setMultiPrincipalManager(manager));
    }

    @Test
    void simpleMultiPrincipalManagerExposesCorrectApiForReactiveStack() {
        SimpleMultiPrincipalManager manager = new SimpleMultiPrincipalManager();

        assertEquals(0, manager.getConfiguredSpns().size());
        assertFalse(manager.hasPrincipalForSpn("HTTP/host@REALM"));
        assertNull(manager.getDefaultSpnegoClient());
        assertNull(manager.getSpnegoClientForSpn("HTTP/host@REALM"));
        assertNotNull(manager.getConfiguredSpns());
    }
}
