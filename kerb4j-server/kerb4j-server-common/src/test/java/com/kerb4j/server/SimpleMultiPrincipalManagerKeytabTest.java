package com.kerb4j.server;

import com.kerb4j.KerberosSecurityTestcase;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Collection;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SimpleMultiPrincipalManagerKeytabTest extends KerberosSecurityTestcase {

    @Test
    void addsAllPrincipalsFromKeytab() throws Exception {
        File keytab = new File(getWorkDir(), "server-aliases.keytab");

        getKdc().createAndExportPrincipals(keytab,
                "HTTP/app.example.com",
                "HTTP/app-alias.example.com");

        SimpleMultiPrincipalManager manager = new SimpleMultiPrincipalManager();
        Collection<String> principals = manager.addPrincipalsFromKeytab(keytab);

        assertTrue(principals.contains("HTTP/app.example.com@EXAMPLE.COM"));
        assertTrue(principals.contains("HTTP/app-alias.example.com@EXAMPLE.COM"));
        assertNotNull(manager.getSpnegoClientForSpn("HTTP/app.example.com@EXAMPLE.COM"));
        assertNotNull(manager.getSpnegoClientForSpn("HTTP/app-alias.example.com@EXAMPLE.COM"));
    }
}
