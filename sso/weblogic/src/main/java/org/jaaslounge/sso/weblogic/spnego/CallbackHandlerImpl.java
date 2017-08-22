package org.jaaslounge.sso.weblogic.spnego;

import java.util.List;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

public class CallbackHandlerImpl implements CallbackHandler {
	private String username;
	private List<String> groups;

	CallbackHandlerImpl(String username, List<String> groups) {
		this.username = username;
		this.groups = groups;
	}

	public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
		for (int i = 0; i < callbacks.length; i++) {

			Callback callback = callbacks[i];

			if (callback instanceof NameCallback) {
				NameCallback nameCallback = (NameCallback) callback;
				nameCallback.setName(username);
			} else if (callback instanceof GroupsCallback) {
				GroupsCallback groupsCallback = (GroupsCallback) callback;
				groupsCallback.setGroups(groups);
			} else {
				throw new UnsupportedCallbackException(callback, "Unrecognized Callback");
			}

		}
	}
}