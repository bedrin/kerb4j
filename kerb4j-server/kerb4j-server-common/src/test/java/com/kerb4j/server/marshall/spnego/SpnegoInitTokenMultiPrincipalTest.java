package com.kerb4j.server.marshall.spnego;

import com.kerb4j.server.marshall.Kerb4JException;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for SPN extraction from SPNEGO/Kerberos tokens.
 */
public class SpnegoInitTokenMultiPrincipalTest {

    // Real SPNEGO token captured from a Windows client authenticating to HTTP/neo.example.org@EXAMPLE.ORG.
    // Nothing sensitive - it is an old expired ticket with no usable keys here.
    private static final String SPNEGO_TOKEN_B64 =
            "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"
          + "eL2PHBfvkne/FgxC";

    @Test
    public void testGetServerPrincipalNameExtractsCanonicalSpnWithRealm() throws Exception {
        byte[] token = Base64.getDecoder().decode(SPNEGO_TOKEN_B64.getBytes(StandardCharsets.UTF_8));
        SpnegoInitToken spnegoInitToken = new SpnegoInitToken(token);
        String spn = spnegoInitToken.getServerPrincipalName();
        // Token targets HTTP/neo.example.org in realm EXAMPLE.ORG
        assertEquals("HTTP/neo.example.org@EXAMPLE.ORG", spn,
                "getServerPrincipalName() must return the full canonical SPN including realm");
    }

    @Test
    public void testGetServerPrincipalNameViaKerberosMechToken() throws Exception {
        byte[] token = Base64.getDecoder().decode(SPNEGO_TOKEN_B64.getBytes(StandardCharsets.UTF_8));
        SpnegoInitToken spnegoInitToken = new SpnegoInitToken(token);
        SpnegoKerberosMechToken mechToken = spnegoInitToken.getSpnegoKerberosMechToken();
        String spn = mechToken.getServerPrincipalName();
        assertEquals("HTTP/neo.example.org@EXAMPLE.ORG", spn,
                "SpnegoKerberosMechToken.getServerPrincipalName() must return the full canonical SPN");
    }

    @Test
    public void testMalformedTokenThrowsKerb4JException() {
        byte[] badToken = new byte[]{0x61}; // wrong tag byte
        assertThrows(Kerb4JException.class, () -> new SpnegoInitToken(badToken));
    }

    @Test
    public void testEmptyTokenThrowsKerb4JException() {
        assertThrows(Kerb4JException.class, () -> new SpnegoInitToken(new byte[0]));
    }
}
