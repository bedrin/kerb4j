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
import java.util.Objects;

/**
 * A stateful, short-lived SPNEGO security context.
 * <p>
 * Instances are not thread-safe. Create a new {@code SpnegoContext} for each request or token exchange.
 */
public class SpnegoContext implements Closeable {

    private static final byte[] EMPTY_BYTE = new byte[0];

    private final SpnegoClient spnegoClient;
    private final Subject subject;
    private final GSSContext gssContext; // TODO: how it should be renewed ?

    /**
     * Creates a context bound to the supplied {@link Subject}.
     *
     * @param subject captured subject used for all GSSContext state-progressing operations
     * @param gssContext GSS context created for the supplied subject
     */
    public SpnegoContext(Subject subject, GSSContext gssContext) {
        this(null, subject, gssContext);
    }

    /**
     * Creates a context bound to {@code spnegoClient.getSubject()} at construction time.
     * <p>
     * This constructor may not match credentials used by a {@link GSSContext} that was created externally. Prefer
     * {@link #SpnegoContext(Subject, GSSContext)} when the subject is already known.
     */
    @Deprecated
    public SpnegoContext(SpnegoClient spnegoClient, GSSContext gssContext) {
        this(spnegoClient, getSubject(spnegoClient), gssContext);
    }

    public SpnegoContext(SpnegoClient spnegoClient, Subject subject, GSSContext gssContext) {
        this.spnegoClient = spnegoClient;
        this.subject = Objects.requireNonNull(subject, "subject must not be null");
        this.gssContext = Objects.requireNonNull(gssContext, "gssContext must not be null");
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
        try {
            return Subject.doAs(subject, (PrivilegedExceptionAction<byte[]>)
                    () -> gssContext.acceptSecContext(token, 0, token.length));
        } catch (PrivilegedActionException e) {
            throw toGssException(e);
        }
    }

    public GSSName getSrcName() throws GSSException {
        return gssContext.getSrcName();
    }

    public GSSContext getGSSContext() {
        return gssContext;
    }

    /**
     * @return client used to create this context, or {@code null} when the context was constructed directly from a
     * {@link Subject}
     */
    @Deprecated
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

    private static Subject getSubject(SpnegoClient spnegoClient) {
        return Objects.requireNonNull(spnegoClient, "spnegoClient must not be null").getSubject();
    }

    private static GSSException toGssException(PrivilegedActionException e) {
        Exception cause = e.getException();
        if (cause instanceof GSSException) {
            return (GSSException) cause;
        }
        GSSException gssException = new GSSException(GSSException.FAILURE);
        gssException.initCause(cause);
        return gssException;
    }
}
