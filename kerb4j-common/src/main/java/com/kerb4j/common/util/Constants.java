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

package com.kerb4j.common.util;

/**
 * Defines constants and parameter names that are used in the
 * web.xml file, and HTTP request headers, etc.
 *
 * <p>
 * This class is primarily used internally or by implementers of
 * custom http clients and by SpnegoFilterConfig.
 *
 */
public class Constants {

    private Constants() {
        // default private
    }

    /**
     * HTTP Response Header <b>WWW-Authenticate</b>.
     *
     * <p>The filter will respond with this header with a value of "Basic"
     * and/or "Negotiate" (based on web.xml file).
     */
    public static final String AUTHN_HEADER = "WWW-Authenticate";

    /**
     * HTTP Request Header <b>Authorization</b>.
     *
     * <p>Clients should send this header where the value is the
     * authentication token(s).
     */
    public static final String AUTHZ_HEADER = "Authorization";

    /**
     * HTTP Response Header <b>Basic</b>.
     *
     * <p>The filter will set this as the value for the "WWW-Authenticate"
     * header if "Basic" auth is allowed (based on web.xml file).
     */
    public static final String BASIC_HEADER = "Basic";

    /**
     * HTTP Response Header <b>Negotiate</b>.
     *
     * <p>The filter will set this as the value for the "WWW-Authenticate"
     * header. Note that the filter may also add another header with
     * a value of "Basic" (if allowed by the web.xml file).
     */
    public static final String NEGOTIATE_HEADER = "Negotiate";

}
