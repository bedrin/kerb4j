package com.kerb4j.server.spring;

import java.io.UnsupportedEncodingException;
import java.util.Collection;
import java.util.HashSet;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;

import org.ietf.jgss.GSSContext;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.codec.Base64;

/**
 * Result of ticket validation
 */
public class SpnegoAuthenticationToken extends AbstractAuthenticationToken {

	private final String username;
	private final byte[] responseToken;
	private final GSSContext gssContext;
	private final String servicePrincipal;

	public SpnegoAuthenticationToken(Collection<? extends GrantedAuthority> authorities, String username, String servicePrincipal, byte[] responseToken, GSSContext gssContext) {
		super(authorities);
		this.username = username;
		this.servicePrincipal = servicePrincipal;
		this.responseToken = responseToken;
		this.gssContext = gssContext;
	}

	public String username() {
		return username;
	}

	public byte[] responseToken() {
		return responseToken;
	}

	public GSSContext getGssContext() {
		return gssContext;
	}

	public Subject subject() {
		final HashSet<KerberosPrincipal> princs = new HashSet<KerberosPrincipal>();
		princs.add(new KerberosPrincipal(servicePrincipal));
		return new Subject(false, princs, new HashSet<Object>(), new HashSet<Object>());
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
			throw new IllegalStateException("Unable to encode response token", e);
		}
	}

	@Override
	public Object getCredentials() {
		return null;
	}

	@Override
	public Object getPrincipal() {
		return null;
	}

}