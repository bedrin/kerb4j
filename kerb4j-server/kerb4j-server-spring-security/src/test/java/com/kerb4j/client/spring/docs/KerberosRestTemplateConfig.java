package com.kerb4j.client.spring.docs;

import com.kerb4j.client.SpnegoClient;
import com.kerb4j.client.spring.SpnegoRestTemplate;

import javax.security.auth.login.LoginException;

public class KerberosRestTemplateConfig {

//tag::snippetA[]
    public void doWithTicketCache() throws LoginException {
        SpnegoRestTemplate restTemplate =
                new SpnegoRestTemplate(SpnegoClient.loginWithTicketCache("user1@EXAMPLE.ORG"));
        restTemplate.getForObject("http://neo.example.org:8080/hello", String.class);
    }
//end::snippetA[]

//tag::snippetB[]
    public void doWithKeytabFile() throws LoginException {
        SpnegoRestTemplate restTemplate =
                new SpnegoRestTemplate(SpnegoClient.loginWithKeyTab("user2@EXAMPLE.ORG", "/tmp/user2.keytab"));
        restTemplate.getForObject("http://neo.example.org:8080/hello", String.class);
    }
//end::snippetB[]

}
