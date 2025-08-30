package com.kerb4j.integration.jdk;

import com.kerb4j.client.SpnegoContext;
import com.kerb4j.integration.api.KerberosContext;
import org.ietf.jgss.GSSName;

import java.io.IOException;

/**
 * JDK GSS API implementation of KerberosContext.
 * This is an adapter that wraps the existing SpnegoContext.
 */
public class JdkKerberosContext implements KerberosContext {

    private final SpnegoContext spnegoContext;

    public JdkKerberosContext(SpnegoContext spnegoContext) {
        this.spnegoContext = spnegoContext;
    }

    @Override
    public void requestCredentialsDelegation() throws Exception {
        spnegoContext.requestCredentialsDelegation();
    }

    @Override
    public byte[] createToken() throws Exception {
        return spnegoContext.createToken();
    }

    @Override
    public String createTokenAsAuthroizationHeader() throws Exception {
        return spnegoContext.createTokenAsAuthroizationHeader();
    }

    @Override
    public byte[] processMutualAuthorization(byte[] data, int offset, int length) throws Exception {
        return spnegoContext.processMutualAuthorization(data, offset, length);
    }

    @Override
    public byte[] acceptToken(byte[] token) throws Exception {
        return spnegoContext.acceptToken(token);
    }

    @Override
    public String getSrcName() throws Exception {
        GSSName gssName = spnegoContext.getSrcName();
        return gssName != null ? gssName.toString() : null;
    }

    @Override
    public boolean isEstablished() {
        return spnegoContext.isEstablished();
    }

    @Override
    public void close() throws IOException {
        spnegoContext.close();
    }

    /**
     * Get the underlying SpnegoContext for backward compatibility.
     * @return the wrapped SpnegoContext
     */
    public SpnegoContext getSpnegoContext() {
        return spnegoContext;
    }
}