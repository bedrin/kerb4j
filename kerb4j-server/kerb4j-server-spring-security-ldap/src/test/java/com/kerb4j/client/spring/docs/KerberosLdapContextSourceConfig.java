package com.kerb4j.client.spring.docs;

import com.kerb4j.client.SpnegoClient;
import com.kerb4j.server.spring.ldap.KerberosLdapContextSource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;
import org.springframework.security.ldap.userdetails.LdapUserDetailsService;

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
    public KerberosLdapContextSource kerberosLdapContextSource() {
        KerberosLdapContextSource contextSource = new KerberosLdapContextSource(adServer);
        contextSource.setSpnegoClient(SpnegoClient.loginWithKeyTab(servicePrincipal, keytabLocation));
        return contextSource;
    }

    @Bean
    public LdapUserDetailsService ldapUserDetailsService(KerberosLdapContextSource kerberosLdapContextSource) {
        FilterBasedLdapUserSearch userSearch =
                new FilterBasedLdapUserSearch(ldapSearchBase, ldapSearchFilter, kerberosLdapContextSource);
        LdapUserDetailsService service = new LdapUserDetailsService(userSearch);
        service.setUserDetailsMapper(new LdapUserDetailsMapper());
        return service;
    }
//end::snippetA[]

}
