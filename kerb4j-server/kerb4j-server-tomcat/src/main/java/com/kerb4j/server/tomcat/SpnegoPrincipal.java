package com.kerb4j.server.tomcat;

import org.apache.catalina.realm.GenericPrincipal;

import java.security.Principal;
import java.util.Collections;
import java.util.List;

/**
 * Represente une identite Active Directory associte y un ensemble de roles.
 * Les roles sont recuperes y la volve lors du premier appel y hasRole.
 * @author damien
 */
public class SpnegoPrincipal extends GenericPrincipal {

	/**
	 * Construit une identite
	 * @param name principal name
	 */
	public SpnegoPrincipal(String name) {
		this(name, Collections.singletonList("AUTHETICATED_USER"));
	}

    public SpnegoPrincipal(String name, List<String> roles) {
        super(name, "N/A", roles);
    }

}