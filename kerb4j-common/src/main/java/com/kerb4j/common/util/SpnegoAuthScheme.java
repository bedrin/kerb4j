/**
 * Copyright (C) 2009 "Darwin V. Felix" <darwinfelix@users.sourceforge.net>
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

package com.kerb4j.common.util;

import com.kerb4j.common.util.base64.Base64Codec;

/**
 * Example schemes are "Negotiate" and "Basic". 
 *
 * <p>See examples and tutorials at 
 * <a href="http://spnego.sourceforge.net" target="_blank">http://spnego.sourceforge.net</a>
 *
 * @author Darwin V. Felix
 *
 */
public class SpnegoAuthScheme {

    /** Zero length byte array. */
    private static final transient byte[] EMPTY_BYTE_ARRAY = new byte[0];

    /** HTTP (Request) "Authorization" Header scheme. */
    private final transient String scheme;

    /** HTTP (Request) scheme token. */
    private final transient String token;

    public SpnegoAuthScheme(final String authScheme, final String authToken) {
        this.scheme = authScheme;
        this.token = authToken;
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
        return (null == this.token) ? EMPTY_BYTE_ARRAY : Base64Codec.decode(this.token);
    }
}
