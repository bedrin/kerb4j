/*
 * Copyright 2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.kerb4j.client.spring.docs;

import com.kerb4j.client.SpnegoClient;
import com.kerb4j.server.spring.ldap.KerberosLdapContextSource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;
import org.springframework.security.ldap.userdetails.LdapUserDetailsService;

import javax.security.auth.login.LoginException;

public class KerberosLdapContextSourceConfig {

//tag::snippetA[]
	@Value("${app.ad-server}")
	private String adServer;

	@Value("${app.service-principal}")
	private String servicePrincipal;

	@Value("${app.keytab-location}")
	private String keytabLocation;

	@Value("${app.ldap-search-base}")
	private String ldapSearchBase;

	@Value("${app.ldap-search-filter}")
	private String ldapSearchFilter;

	@Bean
	public KerberosLdapContextSource kerberosLdapContextSource() throws LoginException {
		KerberosLdapContextSource contextSource = new KerberosLdapContextSource(adServer);
		contextSource.setSpnegoClient(SpnegoClient.loginWithKeyTab(servicePrincipal, keytabLocation));
		return contextSource;
	}

	@Bean
	public LdapUserDetailsService ldapUserDetailsService() throws LoginException {
		FilterBasedLdapUserSearch userSearch =
				new FilterBasedLdapUserSearch(ldapSearchBase, ldapSearchFilter, kerberosLdapContextSource());
		LdapUserDetailsService service = new LdapUserDetailsService(userSearch);
		service.setUserDetailsMapper(new LdapUserDetailsMapper());
		return service;
	}
//end::snippetA[]

}
