package org.jaaslounge.gss;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

public class GSSAuthentication {

	private byte[] responseToken;
	private String username;

	public GSSAuthentication(byte[] token) throws GSSException {
		GSSManager gssManager = GSSManager.getInstance();
		GSSCredential gssCreds = gssManager.createCredential(
				(GSSName) null, GSSCredential.INDEFINITE_LIFETIME,
				(Oid) null, GSSCredential.ACCEPT_ONLY);
		GSSContext gssContext = gssManager.createContext(gssCreds);

		responseToken = gssContext
				.acceptSecContext(token, 0, token.length);

		if (gssContext.isEstablished()) {
			GSSName name = gssContext.getSrcName();
			username = name.toString();
		}
	}

	public byte[] getResponseToken() {
		return responseToken;
	}

	public String getUsername() {
		return username;
	}

}
