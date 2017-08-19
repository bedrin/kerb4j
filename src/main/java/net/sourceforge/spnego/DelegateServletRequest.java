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

import javax.servlet.ServletRequest;

import org.ietf.jgss.GSSCredential;

/**
 * The default installation of Internet Explorer and Active Directory 
 * allow the user's/requester's credential to be delegated.
 *
 * <p>
 * By default, {@link SpnegoHttpURLConnection} has delegation set 
 * to false. To allow delegation, call the <code>requestCredDeleg</code> 
 * method on the <code>SpnegoHttpURLConnection</code> instance.
 * </p>
 * 
 * <p>
 * Also, the server/service's pre-authentication account must be specified as 
 * "Account is trusted for delegation" in Active Directory.
 * </p>
 * 
 * <p>
 * Finally, the server/service's spnego servlet init params must be specified 
 * to allow credential delegation by setting the property 
 * <code>spnego.allow.delegation</code> to true (false by default).
 * </p>
 * 
 * <p>
 * Custom client programs may request their credential to be delegated 
 * by calling the <code>requestCredDeleg</code> on their instance of GSSContext.
 * </p>
 * 
 * <p>
 * Java Application Servers can obtain the delegated credential by casting 
 * the HTTP request.
 * </p>
 * 
 * <p>
 * <b>Example usage:</b>
 * <pre>
 *     if (request instanceof DelegateServletRequest) {
 *         DelegateServletRequest dsr = (DelegateServletRequest) request;
 *         GSSCredential creds = dsr.getDelegatedCredential();
 *         ...
 *     }
 * </pre>
 * </p>
 * 
 * <p>
 * To see a working example and instructions, take a look at the 
 * <a href="http://spnego.sourceforge.net/credential_delegation.html" 
 * target="_blank">credential delegation example</a>. 
 * </p>
 * 
 * @author Darwin V. Felix
 *
 */
public interface DelegateServletRequest extends ServletRequest {

    /**
     * Returns the requester's delegated credential.
     * 
     * <p>
     * Returns null if request has no delegated credential 
     * or if delegated credentials are not supported.
     * </p>
     * 
     * @return delegated credential or null
     */
    GSSCredential getDelegatedCredential();
}
