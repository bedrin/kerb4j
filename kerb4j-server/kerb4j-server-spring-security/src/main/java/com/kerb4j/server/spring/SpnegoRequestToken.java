/*
 * Copyright 2009-2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.kerb4j.server.spring;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

/**
 * <p>Holds the Kerberos/SPNEGO token for requesting a kerberized service and is
 * also the output of <code>SpnegoAuthenticationProvider</code>.</p>
 * <p>Will mostly be created in <code>SpnegoAuthenticationProcessingFilter</code>
 * and authenticated in <code>SpnegoAuthenticationProvider</code>.</p>
 *
 * This token cannot be re-authenticated, as you will get a Kerberos Reply
 * error.
 *
 * @author Mike Wiesner
 * @author Jeremy Stone
 * @since 1.0
 * @see SpnegoAuthenticationProvider
 */
public class SpnegoRequestToken extends AbstractAuthenticationToken {

	private static final long serialVersionUID = 395488921064775014L;

	private final byte[] spnegoInitToken;

    /**
     * Creates an authenticated token, normally used as an output of an
     * authentication provider.
     *
     * @param authorities the authorities which are granted to the user
     * @param spnegoInitToken the SPNEGO Init token
     * @see UserDetails
     */
    public SpnegoRequestToken(Collection<? extends GrantedAuthority> authorities, byte[] spnegoInitToken) {
        super(authorities);
        this.spnegoInitToken = spnegoInitToken;
    }

	/**
	 * Creates an unauthenticated instance which should then be authenticated by
	 * <code>SpnegoAuthenticationProvider</code>.
	 *
	 * @param token Kerberos/SPNEGO token
	 * @see SpnegoAuthenticationProvider
	 */
	public SpnegoRequestToken(byte[] token) {
		this(Collections.<GrantedAuthority>emptySet(), token);
	}

	/**
	 * Calculates hashcode based on the Kerberos token
	 */
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + Arrays.hashCode(spnegoInitToken);
		return result;
	}

	/**
	 * equals() is based only on the Kerberos token
	 */
	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (!super.equals(obj))
			return false;
		if (getClass() != obj.getClass())
			return false;
		SpnegoRequestToken other = (SpnegoRequestToken) obj;
		return Arrays.equals(spnegoInitToken, other.spnegoInitToken);
	}

	@Override
	public Object getCredentials() {
		return null;
	}

	@Override
	public Object getPrincipal() {
		return null;
	}

	@Override
	public void eraseCredentials() {
		super.eraseCredentials();
		Arrays.fill(spnegoInitToken, (byte) 0);
	}

	/**
	 * Returns the Kerberos token
	 * @return the token data
	 */
	public byte[] getToken() {
		return this.spnegoInitToken;
	}

	@Override
	public boolean isAuthenticated() {
		return false;
	}

	@Override
	public void setAuthenticated(boolean authenticated) {
		if (authenticated) throw new IllegalArgumentException();
	}
}
