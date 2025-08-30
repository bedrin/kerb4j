package com.kerb4j.integration.jdk;

import com.kerb4j.client.SpnegoClient;
import com.kerb4j.client.SpnegoContext;
import com.kerb4j.integration.api.KerberosClient;
import com.kerb4j.integration.api.KerberosContext;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosKey;
import java.net.URL;

/**
 * JDK GSS API implementation of KerberosClient.
 * This is an adapter that wraps the existing SpnegoClient.
 */
public class JdkKerberosClient implements KerberosClient {

    private final SpnegoClient spnegoClient;

    public JdkKerberosClient(SpnegoClient spnegoClient) {
        this.spnegoClient = spnegoClient;
    }

    @Override
    public Subject getSubject() {
        return spnegoClient.getSubject();
    }

    @Override
    public KerberosKey[] getKerberosKeys() {
        return spnegoClient.getKerberosKeys();
    }

    @Override
    public KerberosContext createContext(URL url) throws Exception {
        SpnegoContext spnegoContext = spnegoClient.createContext(url);
        return new JdkKerberosContext(spnegoContext);
    }

    @Override
    public KerberosContext createContextForSPN(String spn) throws Exception {
        SpnegoContext spnegoContext = spnegoClient.createContextForSPN(spn);
        return new JdkKerberosContext(spnegoContext);
    }

    @Override
    public KerberosContext createAcceptContext() throws Exception {
        SpnegoContext spnegoContext = spnegoClient.createAcceptContext();
        return new JdkKerberosContext(spnegoContext);
    }

    @Override
    public String createAuthroizationHeader(URL url) throws Exception {
        return spnegoClient.createAuthroizationHeader(url);
    }

    @Override
    public String createAuthroizationHeaderForSPN(String spn) throws Exception {
        return spnegoClient.createAuthroizationHeaderForSPN(spn);
    }

    /**
     * Get the underlying SpnegoClient for backward compatibility.
     * @return the wrapped SpnegoClient
     */
    public SpnegoClient getSpnegoClient() {
        return spnegoClient;
    }
}