/** 
 * Copyright (C) 2009 "Darwin V. Felix" <darwinfelix@users.sourceforge.net>
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

package net.sourceforge.spnego;

import net.sourceforge.spnego.SpnegoHttpFilter.Constants;

/**
 * Example schemes are "Negotiate" and "Basic". 
 * 
 * <p>See examples and tutorials at 
 * <a href="http://spnego.sourceforge.net" target="_blank">http://spnego.sourceforge.net</a>
 * </p>
 * 
 * @author Darwin V. Felix
 *
 */
final class SpnegoAuthScheme {
    
    /** Zero length byte array. */
    private static final transient byte[] EMPTY_BYTE_ARRAY = new byte[0];

    /** HTTP (Request) "Authorization" Header scheme. */ 
    private final transient String scheme;

    /** HTTP (Request) scheme token. */
    private final transient String token;
    
    /** true if Basic Auth scheme. */
    private final transient boolean basicScheme;
    
    /** true if Negotiate scheme. */
    private final transient boolean negotiateScheme;
    
    /** true if NTLM token. */
    private final transient boolean ntlm;

    /**
     * 
     * @param authScheme 
     * @param authToken 
     */
    public SpnegoAuthScheme(final String authScheme, final String authToken) {
        this.scheme = authScheme;
        this.token = authToken;
        
        if (null == authToken || authToken.isEmpty()) {
            this.ntlm = false;
        } else {
            this.ntlm = authToken.startsWith(SpnegoHttpFilter.Constants.NTLM_PROLOG);
        }
        
        this.negotiateScheme = Constants.NEGOTIATE_HEADER.equalsIgnoreCase(authScheme);
        this.basicScheme = Constants.BASIC_HEADER.equalsIgnoreCase(authScheme);
    }
    
    /**
     * Returns true if this SpnegoAuthScheme is of type "Basic".
     * 
     * @return true if Basic Auth scheme
     */
    boolean isBasicScheme() {
        return this.basicScheme;
    }
    
    /**
     * Returns true if this SpnegoAuthScheme is of type "Negotiate".
     * 
     * @return true if Negotiate scheme
     */
    boolean isNegotiateScheme() {
        return this.negotiateScheme;
    }
    /**
     * Returns true if NTLM.
     * 
     * @return true if Servlet Filter received NTLM token
     */
    boolean isNtlmToken() {
        return this.ntlm;
    }

    /**
     * Returns HTTP Authorization scheme.
     * 
     * @return "Negotiate" or "Basic"
     */
    public String getScheme() {
        return this.scheme;
    }

    /**
     * Returns a copy of byte[].
     * 
     * @return copy of token
     */
    public byte[] getToken() {
        return (null == this.token) ? EMPTY_BYTE_ARRAY : Base64.decode(this.token);
    }
}
