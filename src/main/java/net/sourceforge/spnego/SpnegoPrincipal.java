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

import java.security.Principal;

import javax.security.auth.kerberos.KerberosPrincipal;

import org.ietf.jgss.GSSCredential;

/**
 * This class encapsulates a KerberosPrincipal.
 * 
 * <p>This class also has a reference to the client's/requester's 
 * delegated credential (if any). See the {@link DelegateServletRequest} 
 * documentation for more details.</p>
 * 
 * <p>Also, see the delegation examples at 
 * <a href="http://spnego.sourceforge.net" target="_blank">http://spnego.sourceforge.net</a>
 * </p>
 * 
 * @author Darwin V. Felix
 *
 */
public final class SpnegoPrincipal implements Principal {

	private final transient KerberosPrincipal kerberosPrincipal;

	private final transient GSSCredential delegatedCred;
	private final SpnegoLogonInfo logonInfo;

	/**
	 * Constructs a SpnegoPrincipal from the provided String input.
	 *
	 * @param name the principal name
	 */
	public SpnegoPrincipal(final String name) {
		this(name, KerberosPrincipal.KRB_NT_PRINCIPAL);
	}

	/**
	 * Constructs a SpnegoPrincipal from the provided String input
	 * and name type input.
	 *
	 * @param name the principal name
	 * @param nameType the name type of the principal
	 */
	public SpnegoPrincipal(final String name, final int nameType) {
		this(name, nameType, null, null);
	}

	/**
	 * Constructs a SpnegoPrincipal from the provided String input
	 * and name type input.
	 *
	 * @param name the principal name
	 * @param nameType the name type of the principal
	 * @param delegCred this principal's delegated credential (if any)
	 */
	public SpnegoPrincipal(final String name, final int nameType
			, final GSSCredential delegCred
			, final SpnegoLogonInfo logonInfo) {

		this.kerberosPrincipal = new KerberosPrincipal(name, nameType);
		this.delegatedCred = delegCred;
		this.logonInfo = logonInfo;
	}

	/**
	 * Returns this Principal's delegated credential or null.
	 *
	 * @return Principal's delegated credential or null.
	 */
	public GSSCredential getDelegatedCredential() {
		return this.delegatedCred;
	}

	@Override
	public String getName() {
		return this.kerberosPrincipal.getName();
	}

	/**
	 * Returns the name type of the KerberosPrincipal.
	 *
	 * @return name type of the KerberosPrincipal
	 */
	public int getNameType() {
		return this.kerberosPrincipal.getNameType();
	}

	/**
	 * Returns the realm component of this Kerberos principal.
	 *
	 * @return realm component of this Kerberos principal
	 */
	public String getRealm() {
		return this.kerberosPrincipal.getRealm();
	}

	/**
	 * Returns the logon info from the PAC authorization data (if available,
	 * such as, from a Kerberos Ticket that was issued by Active Directory).
	 *
	 * @return logon info of this Kerberos principal, or null, if no such info is available for this principal
	 */
	public SpnegoLogonInfo getLogonInfo() {
		return this.logonInfo;
	}

	@Override
	public int hashCode() {
		return this.kerberosPrincipal.hashCode();
	}

	@Override
	public String toString() {
		return this.kerberosPrincipal.toString();
	}
}
