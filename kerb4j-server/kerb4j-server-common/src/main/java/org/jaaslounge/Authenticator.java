package org.jaaslounge;

import javax.security.auth.login.FailedLoginException;

public interface Authenticator {
    public void authenticate() throws FailedLoginException;

    public void setPrincipalsAndCredentials();
}
