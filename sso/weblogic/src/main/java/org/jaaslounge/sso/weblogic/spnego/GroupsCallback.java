package org.jaaslounge.sso.weblogic.spnego;

import java.util.List;

import javax.security.auth.callback.Callback;

public class GroupsCallback implements Callback {

	List<String> groups;

	public GroupsCallback() {
	}

	public List<String> getGroups() {
		return groups;
	}

	public void setGroups(List<String> groups) {
		this.groups = groups;
	}

}
