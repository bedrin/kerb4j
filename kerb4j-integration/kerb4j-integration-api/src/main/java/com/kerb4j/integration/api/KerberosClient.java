package com.kerb4j.integration.api;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosKey;
import java.net.URL;
import java.security.PrivilegedActionException;

/**
 * Interface for Kerberos client implementations.
 * Provides abstraction over different Kerberos libraries (JDK GSS, Apache Kerby, etc.)
 */
public interface KerberosClient {

    /**
     * Get the authenticated subject.
     * @return the authenticated Subject
     */
    Subject getSubject();

    /**
     * Get Kerberos keys for the authenticated principal.
     * @return array of Kerberos keys, or null if none available
     */
    KerberosKey[] getKerberosKeys();

    /**
     * Create a context for the given URL.
     * @param url target URL
     * @return a new KerberosContext
     * @throws Exception if context creation fails
     */
    KerberosContext createContext(URL url) throws Exception;

    /**
     * Create a context for the given SPN.
     * @param spn Service Principal Name
     * @return a new KerberosContext
     * @throws Exception if context creation fails
     */
    KerberosContext createContextForSPN(String spn) throws Exception;

    /**
     * Create an accept context for validating incoming tokens.
     * @return a new KerberosContext for accepting tokens
     * @throws Exception if context creation fails
     */
    KerberosContext createAcceptContext() throws Exception;

    /**
     * Create an authorization header for the given URL.
     * @param url target URL
     * @return authorization header value
     * @throws Exception if header creation fails
     */
    String createAuthroizationHeader(URL url) throws Exception;

    /**
     * Create an authorization header for the given SPN.
     * @param spn Service Principal Name
     * @return authorization header value
     * @throws Exception if header creation fails
     */
    String createAuthroizationHeaderForSPN(String spn) throws Exception;
}