package com.kerb4j.server.spring.integration;

import com.kerb4j.KerberosSecurityTestcase;
import com.kerb4j.client.SpnegoClient;
import com.kerb4j.server.SimpleMultiPrincipalManager;
import com.kerb4j.server.spring.SpnegoAuthenticationToken;
import com.kerb4j.server.spring.jaas.sun.SunJaasKerberosTicketValidator;
import org.apache.kerby.kerberos.kerb.server.SimpleKdcServer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.FileSystemResource;
import org.springframework.security.authentication.BadCredentialsException;

import java.io.File;
import java.nio.file.Files;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class MultiPrincipalKerberosIntegrationTest extends KerberosSecurityTestcase {

    private static final String REALM = "EXAMPLE.COM";
    private static final String USERNAME = "multiuser";
    private static final String USER_PASSWORD = "password";

    private static final String SERVER_A = "HTTP/server-a.example.com";
    private static final String SERVER_B = "HTTP/server-b.example.com";
    private static final String SERVER_DEFAULT = "HTTP/default.example.com";
    private static final String SERVER_UNKNOWN = "HTTP/unknown.example.com";

    private static final String SERVER_A_SPN = SERVER_A + "@" + REALM;
    private static final String SERVER_B_SPN = SERVER_B + "@" + REALM;
    private static final String SERVER_DEFAULT_SPN = SERVER_DEFAULT + "@" + REALM;
    private static final String SERVER_UNKNOWN_SPN = SERVER_UNKNOWN + "@" + REALM;

    private File keytabA;
    private File keytabB;
    private File keytabDefault;
    private SpnegoClient userClient;

    @BeforeEach
    void setUpKerberosFixtures() throws Exception {
        SimpleKdcServer kdc = getKdc();
        File tempDirectory = Files.createTempDirectory("kerb4j-multi-principal").toFile();
        tempDirectory.deleteOnExit();

        keytabA = new File(tempDirectory, "server-a.keytab");
        keytabB = new File(tempDirectory, "server-b.keytab");
        keytabDefault = new File(tempDirectory, "server-default.keytab");
        keytabA.deleteOnExit();
        keytabB.deleteOnExit();
        keytabDefault.deleteOnExit();

        kdc.createAndExportPrincipals(keytabA, SERVER_A);
        kdc.createAndExportPrincipals(keytabB, SERVER_B);
        kdc.createAndExportPrincipals(keytabDefault, SERVER_DEFAULT);
        kdc.createPrincipal(SERVER_UNKNOWN);
        kdc.createPrincipal(USERNAME, USER_PASSWORD);
        userClient = SpnegoClient.loginWithUsernamePassword(USERNAME, USER_PASSWORD);
    }

    @Test
    void multiPrincipalModeUsesMatchingPrincipalAndFailsClosedForUnknownSpn() throws Exception {
        SunJaasKerberosTicketValidator validator = createMultiPrincipalValidator(false);

        SpnegoAuthenticationToken validToken = validator.validateTicket(createTokenForSpn(SERVER_A));
        assertNotNull(validToken);
        assertTrue(validToken.username().startsWith(USERNAME + "@"));

        assertThrows(BadCredentialsException.class,
                () -> validator.validateTicket(createTokenForSpn(SERVER_UNKNOWN)));
    }

    @Test
    void explicitFallbackInManagerAllowsUnknownSpnResolution() throws Exception {
        SunJaasKerberosTicketValidator validator = createMultiPrincipalValidator(true);

        SpnegoAuthenticationToken fallbackValidatedToken = validator.validateTicket(createTokenForSpn(SERVER_DEFAULT));
        assertNotNull(fallbackValidatedToken);
        assertTrue(fallbackValidatedToken.username().startsWith(USERNAME + "@"));
    }

    @Test
    void malformedTokenFailsClosedWithoutFallback() throws Exception {
        SunJaasKerberosTicketValidator validator = createMultiPrincipalValidator(false);
        assertThrows(BadCredentialsException.class, () -> validator.validateTicket(new byte[]{0x00, 0x01, 0x02}));
    }

    @Test
    void singlePrincipalModeRemainsBackwardCompatible() throws Exception {
        SunJaasKerberosTicketValidator validator = new SunJaasKerberosTicketValidator();
        validator.setServicePrincipal(SERVER_A_SPN);
        validator.setKeyTabLocation(new FileSystemResource(keytabA));
        validator.afterPropertiesSet();

        SpnegoAuthenticationToken validated = validator.validateTicket(createTokenForSpn(SERVER_A));
        assertNotNull(validated);
        assertTrue(validated.username().startsWith(USERNAME + "@"));
    }

    private SunJaasKerberosTicketValidator createMultiPrincipalValidator(boolean withFallback) throws Exception {
        SimpleMultiPrincipalManager manager = new SimpleMultiPrincipalManager();
        manager.addPrincipal(SERVER_A_SPN, keytabA);
        manager.addPrincipal(SERVER_B_SPN, keytabB);
        if (withFallback) {
            manager.addDefaultPrincipal(SERVER_DEFAULT_SPN, keytabDefault);
        }

        SunJaasKerberosTicketValidator validator = new SunJaasKerberosTicketValidator();
        validator.setMultiPrincipalManager(manager);
        validator.afterPropertiesSet();
        return validator;
    }

    private byte[] createTokenForSpn(String servicePrincipalName) throws Exception {
        String authorizationHeader = userClient.createAuthroizationHeaderForSPN(servicePrincipalName);
        String tokenBase64 = authorizationHeader.substring("Negotiate ".length());
        return Base64.getDecoder().decode(tokenBase64);
    }
}
