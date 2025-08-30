package com.kerb4j.integration.kerby;

import com.kerb4j.integration.api.KerberosClient;
import com.kerb4j.integration.api.KerberosClientFactory;

/**
 * Apache Kerby implementation of KerberosClientFactory.
 * This implementation uses Apache Kerby instead of JDK GSS API.
 */
public class KerbyKerberosClientFactory implements KerberosClientFactory {

    @Override
    public KerberosClient loginWithUsernamePassword(String username, String password) throws Exception {
        // For now, use a simplified approach - just pass the username as principal
        return new KerbyKerberosClient(username);
    }

    @Override
    public KerberosClient loginWithUsernamePassword(String username, String password, boolean useCache) throws Exception {
        // For now, use a simplified approach - just pass the username as principal
        return new KerbyKerberosClient(username);
    }

    @Override
    public KerberosClient loginWithKeyTab(String principal, String keyTabLocation) throws Exception {
        // For now, use a simplified approach - just pass the principal
        return new KerbyKerberosClient(principal);
    }

    @Override
    public KerberosClient loginWithKeyTab(String principal, String keyTabLocation, boolean acceptOnly) throws Exception {
        // For now, use a simplified approach - just pass the principal
        return new KerbyKerberosClient(principal);
    }

    @Override
    public KerberosClient loginWithTicketCache(String principal) throws Exception {
        return new KerbyKerberosClient(principal);
    }

    @Override
    public String getImplementationName() {
        return "Apache Kerby";
    }
}