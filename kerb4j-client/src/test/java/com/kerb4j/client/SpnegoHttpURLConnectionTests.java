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
package com.kerb4j.client;

import com.kerb4j.KerberosSecurityTestcase;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.kerby.kerberos.kerb.server.SimpleKdcServer;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
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

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class SpnegoHttpURLConnectionTests extends KerberosSecurityTestcase {

    private static final Log log = LogFactory.getLog(SpnegoHttpURLConnectionTests.class);

    private ConfigurableApplicationContext context;

    @AfterEach
    public void close() {
        if (context != null) {
            context.close();
        }
        context = null;
    }

    @Test
    public void testSpnegoWithForward() throws Exception {

        SimpleKdcServer kdc = getKdc();
        Assertions.assertNotNull(kdc);
        File workDir = getWorkDir();
        String host = InetAddress.getLocalHost().getCanonicalHostName().toLowerCase(); // doesn't work without toLowerCse

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
        MatcherAssert.assertThat(portInitListener.latch.await(10, TimeUnit.SECONDS), CoreMatchers.is(true));
        int port = portInitListener.port;

        final String baseUrl = "http://" + host + ":" + port + "/hello";
        log.info("Connection to: " + baseUrl);

        HttpURLConnection huc = (HttpURLConnection) new URL(baseUrl).openConnection();
        huc.setRequestMethod("GET");
        huc.connect();
        int responseCode = huc.getResponseCode();
        Assertions.assertEquals(401, responseCode);
    }

    @Test
    public void testSpnegoWithSuccessHandler() throws Exception {

        SimpleKdcServer kdc = getKdc();
        Assertions.assertNotNull(kdc);
        File workDir = getWorkDir();
        String host = InetAddress.getLocalHost().getCanonicalHostName().toLowerCase(); // doesn't work without toLowerCse

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
        MatcherAssert.assertThat(portInitListener.latch.await(10, TimeUnit.SECONDS), CoreMatchers.is(true));
        int port = portInitListener.port;

        SpnegoClient spnegoClient = SpnegoClient.loginWithKeyTab(clientPrincipal, clientKeytab.getAbsolutePath());

        {
            HttpURLConnection huc = new SpnegoHttpURLConnection(spnegoClient).connect(new URL("http://" + host + ":" + port + "/hello"));
            BufferedReader br = new BufferedReader(new InputStreamReader(huc.getInputStream()));

            Assertions.assertEquals(200, huc.getResponseCode());
            Assertions.assertEquals("hello", br.readLine());
        }

        {
            //spnegoClient.disconnect();

            // TODO: assert no network communication with KDC here
            // TODO: add test for Replay protection

            HttpURLConnection huc = new SpnegoHttpURLConnection(spnegoClient).connect(new URL("http://" + host + ":" + port + "/hello"));
            BufferedReader br = new BufferedReader(new InputStreamReader(huc.getInputStream()));

            Assertions.assertEquals(200, huc.getResponseCode());
            Assertions.assertEquals("hello", br.readLine());
        }

        // TODO: uncomment
        {
            // now let's test ticket renewal

            Thread.sleep(400_000); // Make it a separate test probably with "slow" classifier somehow

            HttpURLConnection huc = new SpnegoHttpURLConnection(spnegoClient).connect(new URL("http://" + host + ":" + port + "/hello"));
            BufferedReader br = new BufferedReader(new InputStreamReader(huc.getInputStream()));

            Assertions.assertEquals(200, huc.getResponseCode());
            Assertions.assertEquals("hello", br.readLine());
        }
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
