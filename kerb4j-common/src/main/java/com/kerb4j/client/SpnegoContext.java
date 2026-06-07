package com.kerb4j.client;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSName;

import javax.security.auth.Subject;
import java.io.Closeable;
import java.io.IOException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Base64;

public class SpnegoContext implements Closeable {

    private static final byte[] EMPTY_BYTE = new byte[0];

    private final SpnegoClient spnegoClient;
    private final Subject subject;
    private final GSSContext gssContext; // TODO: how it should be renewed ?

    public SpnegoContext(SpnegoClient spnegoClient, GSSContext gssContext) {
        this(spnegoClient, spnegoClient.getSubject(), gssContext);
    }

    public SpnegoContext(SpnegoClient spnegoClient, Subject subject, GSSContext gssContext) {
        this.spnegoClient = spnegoClient;
        this.subject = subject;
        this.gssContext = gssContext;
    }

    public void requestCredentialsDelegation() throws GSSException {
        gssContext.requestCredDeleg(true);
    }

    public byte[] createToken() throws PrivilegedActionException {
        return Subject.doAs(subject, (PrivilegedExceptionAction<byte[]>) () -> gssContext.initSecContext(EMPTY_BYTE, 0, 0)
        );
    }

    public String createTokenAsAuthroizationHeader() throws PrivilegedActionException {
        return "Negotiate " + Base64.getEncoder().encodeToString(createToken());
    }

    public byte[] processMutualAuthorization(final byte[] data, final int offset, final int length) throws PrivilegedActionException {
        return Subject.doAs(subject, (PrivilegedExceptionAction<byte[]>) () -> gssContext.initSecContext(data, offset, length)
        );
    }

    public byte[] acceptToken(byte[] token) throws GSSException {
        return this.gssContext.acceptSecContext(token, 0, token.length);
    }

    public GSSName getSrcName() throws GSSException {
        return gssContext.getSrcName();
    }

    public GSSContext getGSSContext() {
        return gssContext;
    }

    public SpnegoClient getSpnegoClient() {
        return spnegoClient;
    }

    public boolean isEstablished() {
        return gssContext.isEstablished();
    }

    public void close() throws IOException {
        try {
            gssContext.dispose();
        } catch (GSSException e) {
            throw new IOException(e);
        }
    }
}
