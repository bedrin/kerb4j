package com.kerb4j.server;

import com.kerb4j.KerberosSecurityTestcase;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Collection;

import static org.junit.jupiter.api.Assertions.assertTrue;

class KeytabPrincipalReaderTest extends KerberosSecurityTestcase {

    @Test
    void readsAllPrincipalsFromKeytab() throws Exception {
        File keytab = new File(getWorkDir(), "aliases.keytab");

        getKdc().createAndExportPrincipals(keytab,
                "HTTP/app.example.com",
                "HTTP/app-alias.example.com");

        Collection<String> principals = KeytabPrincipalReader.getPrincipals(keytab);

        assertTrue(principals.contains("HTTP/app.example.com@EXAMPLE.COM"));
        assertTrue(principals.contains("HTTP/app-alias.example.com@EXAMPLE.COM"));
    }
}
