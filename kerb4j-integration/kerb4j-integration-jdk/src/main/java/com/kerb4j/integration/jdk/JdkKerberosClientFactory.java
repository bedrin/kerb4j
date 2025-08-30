package com.kerb4j.integration.jdk;

import com.kerb4j.client.SpnegoClient;
import com.kerb4j.integration.api.KerberosClient;
import com.kerb4j.integration.api.KerberosClientFactory;

/**
 * JDK GSS API implementation of KerberosClientFactory.
 * This is an adapter that wraps the existing SpnegoClient to provide the new API.
 */
public class JdkKerberosClientFactory implements KerberosClientFactory {

    @Override
    public KerberosClient loginWithUsernamePassword(String username, String password) throws Exception {
        SpnegoClient spnegoClient = SpnegoClient.loginWithUsernamePassword(username, password);
        return new JdkKerberosClient(spnegoClient);
    }

    @Override
    public KerberosClient loginWithUsernamePassword(String username, String password, boolean useCache) throws Exception {
        SpnegoClient spnegoClient = SpnegoClient.loginWithUsernamePassword(username, password, useCache);
        return new JdkKerberosClient(spnegoClient);
    }

    @Override
    public KerberosClient loginWithKeyTab(String principal, String keyTabLocation) throws Exception {
        SpnegoClient spnegoClient = SpnegoClient.loginWithKeyTab(principal, keyTabLocation);
        return new JdkKerberosClient(spnegoClient);
    }

    @Override
    public KerberosClient loginWithKeyTab(String principal, String keyTabLocation, boolean acceptOnly) throws Exception {
        SpnegoClient spnegoClient = SpnegoClient.loginWithKeyTab(principal, keyTabLocation, acceptOnly);
        return new JdkKerberosClient(spnegoClient);
    }

    @Override
    public KerberosClient loginWithTicketCache(String principal) throws Exception {
        SpnegoClient spnegoClient = SpnegoClient.loginWithTicketCache(principal);
        return new JdkKerberosClient(spnegoClient);
    }

    @Override
    public String getImplementationName() {
        return "JDK";
    }
}