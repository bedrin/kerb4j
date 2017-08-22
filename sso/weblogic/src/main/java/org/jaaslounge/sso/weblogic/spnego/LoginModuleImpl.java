package org.jaaslounge.sso.weblogic.spnego;

import java.io.IOException;
import java.security.Principal;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import weblogic.security.principal.WLSGroupImpl;
import weblogic.security.principal.WLSUserImpl;

public class LoginModuleImpl implements LoginModule {

	private Subject subject;
	private CallbackHandler callbackHandler;

	private boolean loginSucceeded;
	private boolean principalsInSubject;
	private Vector<Principal> principalsBeforeCommit = new Vector<Principal>();

	public void initialize(Subject subject, CallbackHandler callbackHandler,
			Map<String, ?> sharedState, Map<String, ?> options) {
		this.subject = subject;
		this.callbackHandler = callbackHandler;
	}

	public boolean login() throws LoginException {
		Callback[] callbacks;
		callbacks = new Callback[2];
		callbacks[0] = new NameCallback("blank");
		callbacks[1] = new GroupsCallback();
		try {
			callbackHandler.handle(callbacks);
		} catch (IOException e) {
			throw new LoginException(e.toString());
		} catch (UnsupportedCallbackException e) {
			throw new LoginException(e.toString());
		}

		String username = ((NameCallback) callbacks[0]).getName();
		if(username == null || username.length() == 0) {
			throw new FailedLoginException("Authentication failed: Could not retrieve username from IdentityAsserter");
		}
		loginSucceeded = true;
		principalsBeforeCommit.add(new WLSUserImpl(username));
		List<String> groups = ((GroupsCallback) callbacks[1]).getGroups();
		if (groups != null) {
			for (String groupName : groups) {
				principalsBeforeCommit.add(new WLSGroupImpl(groupName));
			}
		}
		return loginSucceeded;
	}

	public boolean commit() throws LoginException {
		if (loginSucceeded) {
			subject.getPrincipals().addAll(principalsBeforeCommit);
			principalsInSubject = true;
			return true;
		} else {
			return false;
		}
	}

	public boolean abort() throws LoginException {
		if (principalsInSubject) {
			subject.getPrincipals().removeAll(principalsBeforeCommit);
			principalsInSubject = false;
		}
		return true;
	}

	public boolean logout() throws LoginException {
		return true;
	}

}
