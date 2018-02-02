package com.kerb4j.server.marshall.pac;

import com.kerb4j.server.marshall.Kerb4JException;

/**
 * Structure representing the PAC_CREDENTIAL_TYPE record
 * 
 * @author jbbugeau
 */
public class PacCredentialType {

    private static final int MINIMAL_BUFFER_SIZE = 32;

    private byte[] credentialType;

    public PacCredentialType(byte[] data) throws Kerb4JException {
        credentialType = data;
        if(!isCredentialTypeCorrect()) {
            throw new Kerb4JException("pac.credentialtype.malformed");
        }
    }

    public boolean isCredentialTypeCorrect() {
        return credentialType != null && credentialType.length > MINIMAL_BUFFER_SIZE;
    }

}
