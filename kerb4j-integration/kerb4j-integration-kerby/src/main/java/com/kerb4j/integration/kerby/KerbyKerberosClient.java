package com.kerb4j.integration.kerby;

import com.kerb4j.integration.api.KerberosClient;
import com.kerb4j.integration.api.KerberosContext;
import org.apache.kerby.kerberos.kerb.client.KrbClient;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.kerberos.KerberosPrincipal;
import java.net.URL;
import java.util.HashSet;
import java.util.Set;

/**
 * Apache Kerby implementation of KerberosClient.
 * This implementation uses Apache Kerby library instead of JDK GSS API.
 */
public class KerbyKerberosClient implements KerberosClient {

    private final KrbClient krbClient;
    private final Subject subject;
    private final String principal;

    public KerbyKerberosClient(String principal) throws Exception {
        this.principal = principal;
        this.krbClient = new KrbClient();
        this.subject = createSubject();
    }

    private Subject createSubject() throws Exception {
        Subject subject = new Subject();
        
        // Add principal
        Set<KerberosPrincipal> principals = new HashSet<>();
        principals.add(new KerberosPrincipal(principal));
        subject.getPrincipals().addAll(principals);
        
        // Initialize Kerby client
        krbClient.init();
        
        return subject;
    }

    @Override
    public Subject getSubject() {
        return subject;
    }

    @Override
    public KerberosKey[] getKerberosKeys() {
        // For Apache Kerby implementation, we would need to extract keys
        // from the keytab or other credential sources
        // This is a simplified implementation
        return new KerberosKey[0];
    }

    @Override
    public KerberosContext createContext(URL url) throws Exception {
        String spn = "HTTP/" + url.getHost();
        return createContextForSPN(spn);
    }

    @Override
    public KerberosContext createContextForSPN(String spn) throws Exception {
        return new KerbyKerberosContext(krbClient, subject, spn, false);
    }

    @Override
    public KerberosContext createAcceptContext() throws Exception {
        return new KerbyKerberosContext(krbClient, subject, null, true);
    }

    @Override
    public String createAuthroizationHeader(URL url) throws Exception {
        try (KerberosContext context = createContext(url)) {
            return context.createTokenAsAuthroizationHeader();
        }
    }

    @Override
    public String createAuthroizationHeaderForSPN(String spn) throws Exception {
        try (KerberosContext context = createContextForSPN(spn)) {
            return context.createTokenAsAuthroizationHeader();
        }
    }
}