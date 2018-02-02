package com.kerb4j.server.spring;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.codec.Base64;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosKey;
import java.io.UnsupportedEncodingException;
import java.util.Collection;

/**
 * Result of ticket validation
 */
public class SpnegoAuthenticationToken extends SpnegoRequestToken {

	private final String username;
	private final byte[] responseToken;
	private final Subject subject;
	private final KerberosKey[] kerberosKeys;

	// TODO: should contain everything for delegated auhentication

	public SpnegoAuthenticationToken(Collection<? extends GrantedAuthority> authorities, byte[] spnegoInitToken, String username, byte[] responseToken, Subject subject, KerberosKey[] kerberosKeys) {
		super(authorities, spnegoInitToken);
		this.username = username;
		this.responseToken = responseToken;
		this.subject = subject;
		this.kerberosKeys = kerberosKeys;
	}

	public SpnegoAuthenticationToken(byte[] token, String username, byte[] responseToken, Subject subject, KerberosKey[] kerberosKeys) {
		super(token);
		this.username = username;
		this.responseToken = responseToken;
		this.subject = subject;
        this.kerberosKeys = kerberosKeys;
	}

	public String username() {
		return username;
	}

	public byte[] responseToken() {
		return responseToken;
	}

	/**
	 * Determines whether an authenticated token has a response token
	 *
	 * @return whether a response token is available
	 */
	public boolean hasResponseToken() {
		return responseToken() != null;
	}

	/**
	 * Gets the (Base64) encoded response token assuming one is available.
	 *
	 * @return encoded response token
	 */
	public String getEncodedResponseToken() {
		if (!hasResponseToken())
			throw new IllegalStateException("Unauthenticated or no response token");

		try {
			return new String(Base64.encode(responseToken()), "UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new IllegalStateException("Unable to encodeImpl response token", e);
		}
	}

    @Override
    public boolean isAuthenticated() {
        return true;
    }

    @Override
    public void setAuthenticated(boolean authenticated) {
        if (!authenticated) throw new IllegalArgumentException();
    }

    @Override
	public Object getPrincipal() {
		return username; // TODO: should return UserDetails
	}

	public Subject getSubject() {
		return subject;
	}

	public KerberosKey[] getKerberosKeys() {
		return kerberosKeys;
	}
}