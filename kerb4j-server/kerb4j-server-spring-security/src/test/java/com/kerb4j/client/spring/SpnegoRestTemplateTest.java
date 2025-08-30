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
package com.kerb4j.client.spring;

import com.kerb4j.KerberosSecurityTestcase;
import com.kerb4j.client.SpnegoClient;
import org.apache.kerby.kerberos.kerb.server.SimpleKdcServer;
import org.apache.kerby.kerberos.kerb.type.base.NameType;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.servlet.context.ServletWebServerInitializedEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KeyTab;
import java.io.File;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class SpnegoRestTemplateTest extends KerberosSecurityTestcase {

    private ConfigurableApplicationContext context;

    @AfterEach
    public void close() {
        if (context != null) {
            context.close();
        }
        context = null;
    }

    @Test
    public void testSpnegoClientNotInitiator() throws Exception {

        SimpleKdcServer kdc = getKdc();
        File workDir = getWorkDir();
        String host = "localhost";

        String serverPrincipal = "HTTP/" + host;
        File serverKeytab = new File(workDir, "acceptOnly.keytab");
        if (serverKeytab.exists()) {
            assertTrue(serverKeytab.delete());
        }
        kdc.createAndExportPrincipals(serverKeytab, serverPrincipal);

        SpnegoClient spnegoClient = SpnegoClient.loginWithKeyTab(serverPrincipal, serverKeytab.getAbsolutePath(), true);

        Subject subject = spnegoClient.getSubject();

        Set<KerberosPrincipal> principals = subject.getPrincipals(KerberosPrincipal.class);
        Assertions.assertEquals(1, principals.size());

        KerberosPrincipal kerberosPrincipal = principals.iterator().next();
        Assertions.assertEquals(serverPrincipal + "@EXAMPLE.COM", kerberosPrincipal.getName());
        Assertions.assertEquals("EXAMPLE.COM", kerberosPrincipal.getRealm());
        Assertions.assertEquals(NameType.NT_PRINCIPAL.getValue(), kerberosPrincipal.getNameType());

        Set<KeyTab> privateCredentials = subject.getPrivateCredentials(KeyTab.class);
        Assertions.assertEquals(1, privateCredentials.size());

        KeyTab keyTab = privateCredentials.iterator().next();
        assertTrue(keyTab.exists());
        assertTrue(keyTab.isBound());
        Assertions.assertEquals(kerberosPrincipal, keyTab.getPrincipal());

        KerberosKey[] keyTabKeys = keyTab.getKeys(kerberosPrincipal);

        Assertions.assertEquals(kerberosPrincipal, keyTabKeys[0].getPrincipal());
        Assertions.assertEquals(1, keyTabKeys[0].getVersionNumber());

    }

    @Test
    public void testSpnego() throws Exception {

        SimpleKdcServer kdc = getKdc();
        File workDir = getWorkDir();
        String host = "localhost";

        String serverPrincipal = "HTTP/" + host;
        File serverKeytab = new File(workDir, "server.keytab");
        kdc.createAndExportPrincipals(serverKeytab, serverPrincipal);

        String clientPrincipal = "client/" + host;
        File clientKeytab = new File(workDir, "client.keytab");
        kdc.createAndExportPrincipals(clientKeytab, clientPrincipal);

        SpringApplication springApplication = new SpringApplicationBuilder(
                WebSecurityConfig.class,
                VanillaWebConfiguration.class,
                TestAppConfiguration.class).application();
        context = springApplication.run(
                "--security.basic.enabled=true",
                "--security.user.name=username",
                "--security.user.password=password",
                "--serverPrincipal=" + serverPrincipal,
                "--serverKeytab=" + serverKeytab.getAbsolutePath()
        );

        PortInitListener portInitListener = context.getBean(PortInitListener.class);
        assertThat(portInitListener.latch.await(10, TimeUnit.SECONDS), is(true));
        int port = portInitListener.port;

        {
            SpnegoRestTemplate restTemplate = new SpnegoRestTemplate(SpnegoClient.loginWithKeyTab(clientPrincipal, clientKeytab.getAbsolutePath(), false));
            String response = restTemplate.getForObject("http://" + host + ":" + port + "/hello", String.class);
            assertThat(response, is("hello"));
        }

        {
            try {
                SpnegoClient spnegoClient = SpnegoClient.loginWithKeyTab(clientPrincipal, clientKeytab.getAbsolutePath(), true);
                SpnegoRestTemplate restTemplate = new SpnegoRestTemplate(spnegoClient);
                restTemplate.getForObject("http://" + host + ":" + port + "/hello", String.class);
                fail("Should have failed when accept only client is used as a client");
            } catch (Exception e) {
                assertNotNull(e);
            }
        }
    }

    @Test
    public void testServerRequests() throws Exception {

        SimpleKdcServer kdc = getKdc();
        File workDir = getWorkDir();
        String host = "localhost";

        String serverPrincipal = "HTTP/" + host;
        File serverKeytab = new File(workDir, "server.keytab");
        kdc.createAndExportPrincipals(serverKeytab, serverPrincipal);

        String clientPrincipal = "client/" + host;
        File clientKeytab = new File(workDir, "client.keytab");
        kdc.createAndExportPrincipals(clientKeytab, clientPrincipal);

        SpringApplication springApplication = new SpringApplicationBuilder(
                WebSecurityConfig.class,
                VanillaWebConfiguration.class,
                TestAppConfiguration.class).application();
        context = springApplication.run(
                "--security.basic.enabled=true",
                "--security.user.name=username",
                "--security.user.password=password",
                "--serverPrincipal=" + serverPrincipal,
                "--serverKeytab=" + serverKeytab.getAbsolutePath()
        );

        PortInitListener portInitListener = context.getBean(PortInitListener.class);
        assertThat(portInitListener.latch.await(10, TimeUnit.SECONDS), is(true));
        int port = portInitListener.port;

        SpnegoRestTemplate spnegoRestTemplate = new SpnegoRestTemplate(SpnegoClient.loginWithKeyTab(clientPrincipal, clientKeytab.getAbsolutePath()));

        String response = spnegoRestTemplate.getForObject("http://" + host + ":" + port + "/", String.class);
        assertThat(response, is("home"));
    }

    @Test
    public void testSpnegoWithPasswordOnServer() throws Exception {

        SimpleKdcServer kdc = getKdc();
        File workDir = getWorkDir();
        String host = "localhost";

        String serverPrincipal = "HTTP/" + host;
        String serverPassword = "TestPassword";
        kdc.createPrincipal(serverPrincipal, serverPassword);

        String clientPrincipal = "client/" + host;
        File clientKeytab = new File(workDir, "client.keytab");
        kdc.createAndExportPrincipals(clientKeytab, clientPrincipal);

        SpringApplication springApplication = new SpringApplicationBuilder(
                WebSecurityConfigServerPassword.class,
                VanillaWebConfiguration.class,
                TestAppConfiguration.class).application();
        context = springApplication.run(
                "--security.basic.enabled=true",
                "--security.user.name=username",
                "--security.user.password=password",
                "--serverPrincipal=" + serverPrincipal,
                "--serverPassword=" + serverPassword
        );

        PortInitListener portInitListener = context.getBean(PortInitListener.class);
        assertThat(portInitListener.latch.await(10, TimeUnit.SECONDS), is(true));
        int port = portInitListener.port;

        SpnegoRestTemplate restTemplate = new SpnegoRestTemplate(SpnegoClient.loginWithKeyTab(clientPrincipal, clientKeytab.getAbsolutePath()));

        String response = restTemplate.getForObject("http://" + host + ":" + port + "/hello", String.class);
        assertThat(response, is("hello"));
    }

    @Test
    public void testSpnegoWithForward() throws Exception {

        SimpleKdcServer kdc = getKdc();
        File workDir = getWorkDir();
        String host = "localhost";

        String serverPrincipal = "HTTP/" + host;
        File serverKeytab = new File(workDir, "server.keytab");
        kdc.createAndExportPrincipals(serverKeytab, serverPrincipal);

        SpringApplication springApplication = new SpringApplicationBuilder(
                WebSecurityConfigSpnegoForward.class,
                VanillaWebConfiguration.class,
                TestAppConfiguration.class).application();
        context = springApplication.run(
                "--security.basic.enabled=true",
                "--security.user.name=username",
                "--security.user.password=password",
                "--serverPrincipal=" + serverPrincipal,
                "--serverKeytab=" + serverKeytab.getAbsolutePath()
        );

        PortInitListener portInitListener = context.getBean(PortInitListener.class);
        assertThat(portInitListener.latch.await(10, TimeUnit.SECONDS), is(true));
        int port = portInitListener.port;

        // TODO: should tweak minikdc so that we can use kerberos principals
        //       which are not valid, for now just use plain RestTemplate

        // just checking that we get 401 which we skip and
        // get login page content
        RestTemplate restTemplate = new RestTemplate();
        restTemplate.setErrorHandler(new DefaultResponseErrorHandler() {
            @Override
            public void handleError(ClientHttpResponse response) {
            }
        });

        String response = restTemplate.getForObject("http://" + host + ":" + port + "/hello", String.class);
        assertThat(response, is("login"));
    }

    @Test
    public void testSpnegoWithSuccessHandler() throws Exception {

        SimpleKdcServer kdc = getKdc();
        File workDir = getWorkDir();
        String host = "localhost";

        String serverPrincipal = "HTTP/" + host;
        File serverKeytab = new File(workDir, "server.keytab");
        kdc.createAndExportPrincipals(serverKeytab, serverPrincipal);

        String clientPrincipal = "client/" + host;
        File clientKeytab = new File(workDir, "client.keytab");
        kdc.createAndExportPrincipals(clientKeytab, clientPrincipal);

        SpringApplication springApplication = new SpringApplicationBuilder(
                WebSecurityConfigSuccessHandler.class,
                VanillaWebConfiguration.class,
                TestAppConfiguration.class).application();
        context = springApplication.run(
                "--security.basic.enabled=true",
                "--security.user.name=username",
                "--security.user.password=password",
                "--serverPrincipal=" + serverPrincipal,
                "--serverKeytab=" + serverKeytab.getAbsolutePath()
        );

        PortInitListener portInitListener = context.getBean(PortInitListener.class);
        assertThat(portInitListener.latch.await(10, TimeUnit.SECONDS), is(true));
        int port = portInitListener.port;

        SpnegoRestTemplate restTemplate = new SpnegoRestTemplate(SpnegoClient.loginWithKeyTab(clientPrincipal, clientKeytab.getAbsolutePath()));

        String response = restTemplate.getForObject("http://" + host + ":" + port + "/hello", String.class);
        assertThat(response, is("hello"));
    }

    protected static class PortInitListener implements ApplicationListener<ServletWebServerInitializedEvent> {

        public int port;
        public CountDownLatch latch = new CountDownLatch(1);

        @Override
        public void onApplicationEvent(ServletWebServerInitializedEvent event) {
            port = event.getWebServer().getPort();
            latch.countDown();
        }
    }

    @Configuration
    protected static class VanillaWebConfiguration {

        @Bean
        public PortInitListener portListener() {
            return new PortInitListener();
        }

        @Bean
        public TomcatServletWebServerFactory tomcatServletWebServerFactory() {
            TomcatServletWebServerFactory factory = new TomcatServletWebServerFactory();
            factory.setPort(0);
            return factory;
        }
    }

}
