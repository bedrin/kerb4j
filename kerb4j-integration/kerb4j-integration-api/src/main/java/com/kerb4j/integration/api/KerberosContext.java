package com.kerb4j.integration.api;

import java.io.Closeable;
import java.security.PrivilegedActionException;

/**
 * Interface for Kerberos security context implementations.
 * Provides abstraction over different Kerberos libraries for token handling.
 */
public interface KerberosContext extends Closeable {

    /**
     * Request credentials delegation.
     * @throws Exception if delegation request fails
     */
    void requestCredentialsDelegation() throws Exception;

    /**
     * Create a security token.
     * @return the security token bytes
     * @throws Exception if token creation fails
     */
    byte[] createToken() throws Exception;

    /**
     * Create a security token as an HTTP Authorization header value.
     * @return authorization header value (e.g., "Negotiate base64token")
     * @throws Exception if token creation fails
     */
    String createTokenAsAuthroizationHeader() throws Exception;

    /**
     * Process mutual authentication response.
     * @param data response data
     * @param offset offset in the data
     * @param length length of the data
     * @return processed response bytes
     * @throws Exception if processing fails
     */
    byte[] processMutualAuthorization(byte[] data, int offset, int length) throws Exception;

    /**
     * Accept an incoming security token (server side).
     * @param token the security token to accept
     * @return response token bytes, or null if no response needed
     * @throws Exception if token acceptance fails
     */
    byte[] acceptToken(byte[] token) throws Exception;

    /**
     * Get the source name (client principal) from an accepted token.
     * @return the source name, or null if not available
     * @throws Exception if name retrieval fails
     */
    String getSrcName() throws Exception;

    /**
     * Check if the security context is established.
     * @return true if context is established, false otherwise
     */
    boolean isEstablished();
}