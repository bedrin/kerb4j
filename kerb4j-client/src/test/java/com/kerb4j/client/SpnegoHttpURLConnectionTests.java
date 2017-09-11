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

import org.junit.After;
import org.junit.Test;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.PropertyPlaceholderAutoConfiguration;
import org.springframework.boot.autoconfigure.security.SecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.web.*;
import org.springframework.boot.context.embedded.EmbeddedServletContainerInitializedEvent;
import org.springframework.boot.context.embedded.tomcat.TomcatEmbeddedServletContainerFactory;
import org.springframework.context.ApplicationListener;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import com.kerb4j.KerberosSecurityTestcase;
import com.kerb4j.MiniKdc;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.lang.annotation.*;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

public class SpnegoHttpURLConnectionTests extends KerberosSecurityTestcase {

	private ConfigurableApplicationContext context;

	@After
	public void close() {
		if (context != null) {
			context.close();
		}
		context = null;
	}

    @Test
    public void testSpnegoWithForward() throws Exception {

		MiniKdc kdc = getKdc();
		File workDir = getWorkDir();
		String host = InetAddress.getLocalHost().getCanonicalHostName().toLowerCase(); // doesn't work without toLowerCse


		String serverPrincipal = "HTTP/" + host;
		File serverKeytab = new File(workDir, "src/test/resources/server.keytab");
		kdc.createPrincipal(serverKeytab, serverPrincipal);

		context = SpringApplication.run(new Object[] { WebSecurityConfigSpnegoForward.class, VanillaWebConfiguration.class,
				WebConfiguration.class }, new String[] { "--security.basic.enabled=true",
				"--security.user.name=username", "--security.user.password=password",
				"--serverPrincipal=" + serverPrincipal, "--serverKeytab=" + serverKeytab.getAbsolutePath() });

		PortInitListener portInitListener = context.getBean(PortInitListener.class);
		assertThat(portInitListener.latch.await(10, TimeUnit.SECONDS), is(true));
		int port = portInitListener.port;

		// TODO: should tweak minikdc so that we can use kerberos principals
		//       which are not valid, for now just use plain RestTemplate

		HttpURLConnection huc = (HttpURLConnection)
				new URL("http://" + host + ":" + port + "/hello").openConnection();

		assertEquals(401, huc.getResponseCode());

		BufferedReader br = new BufferedReader(new InputStreamReader(huc.getErrorStream()));
		assertEquals("login", br.readLine());

    }

    @Test
    public void testSpnegoWithSuccessHandler() throws Exception {

		MiniKdc kdc = getKdc();
		File workDir = getWorkDir();
		String host = InetAddress.getLocalHost().getCanonicalHostName().toLowerCase(); // doesn't work without toLowerCse

		String serverPrincipal = "HTTP/" + host;
		File serverKeytab = new File(workDir, "server.keytab");
		kdc.createPrincipal(serverKeytab, serverPrincipal);

		String clientPrincipal = "client/" + host;
		File clientKeytab = new File(workDir, "client.keytab");
		kdc.createPrincipal(clientKeytab, clientPrincipal);


		context = SpringApplication.run(new Object[] { WebSecurityConfigSuccessHandler.class, VanillaWebConfiguration.class,
				WebConfiguration.class }, new String[] { "--security.basic.enabled=true",
				"--security.user.name=username", "--security.user.password=password",
				"--serverPrincipal=" + serverPrincipal, "--serverKeytab=" + serverKeytab.getAbsolutePath() });

		PortInitListener portInitListener = context.getBean(PortInitListener.class);
		assertThat(portInitListener.latch.await(10, TimeUnit.SECONDS), is(true));
		int port = portInitListener.port;

		SpnegoClient spnegoClient = SpnegoClient.loginWithKeyTab(clientPrincipal, clientKeytab.getAbsolutePath());

		{
			HttpURLConnection huc = new SpnegoHttpURLConnection(spnegoClient).connect(new URL("http://" + host + ":" + port + "/hello"));
			BufferedReader br = new BufferedReader(new InputStreamReader(huc.getInputStream()));

			assertEquals(200, huc.getResponseCode());
			assertEquals("home", br.readLine());
		}

		{
			//spnegoClient.disconnect();

			// TODO: assert no network communication with KDC here
			// TODO: add test for Replay protection

			HttpURLConnection huc = new SpnegoHttpURLConnection(spnegoClient).connect(new URL("http://" + host + ":" + port + "/hello"));
			BufferedReader br = new BufferedReader(new InputStreamReader(huc.getInputStream()));

			assertEquals(200, huc.getResponseCode());
			assertEquals("home", br.readLine());
		}

		// TODO: uncomment
		{
			// now let's test ticket renewal

			Thread.sleep(400_000); // Make it a separate test probably with "slow" classifier somehow

			HttpURLConnection huc = new SpnegoHttpURLConnection(spnegoClient).connect(new URL("http://" + host + ":" + port + "/hello"));
			BufferedReader br = new BufferedReader(new InputStreamReader(huc.getInputStream()));

			assertEquals(200, huc.getResponseCode());
			assertEquals("home", br.readLine());
		}
    }

	protected static class PortInitListener implements ApplicationListener<EmbeddedServletContainerInitializedEvent> {

		public int port;
		public CountDownLatch latch = new CountDownLatch(1);

		@Override
		public void onApplicationEvent(EmbeddedServletContainerInitializedEvent event) {
			port = event.getEmbeddedServletContainer().getPort();
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
    	public TomcatEmbeddedServletContainerFactory tomcatEmbeddedServletContainerFactory() {
    	    TomcatEmbeddedServletContainerFactory factory = new TomcatEmbeddedServletContainerFactory();
    	    factory.setPort(0);
    	    return factory;
    	}
    }

    @MinimalWebConfiguration
    @Import(SecurityAutoConfiguration.class)
    @Controller
	protected static class WebConfiguration {

    	@RequestMapping(method = RequestMethod.GET)
    	@ResponseBody
    	public String home() {
    		return "home";
    	}

    	@RequestMapping(method = RequestMethod.GET, value = "/login")
    	@ResponseBody
    	public String login() {
    		return "login";
    	}

	}

    @Configuration
    @Target(ElementType.TYPE)
    @Retention(RetentionPolicy.RUNTIME)
    @Documented
    @Import({ EmbeddedServletContainerAutoConfiguration.class,
                    ServerPropertiesAutoConfiguration.class,
                    DispatcherServletAutoConfiguration.class, WebMvcAutoConfiguration.class,
                    HttpMessageConvertersAutoConfiguration.class,
                    ErrorMvcAutoConfiguration.class, PropertyPlaceholderAutoConfiguration.class })
    protected @interface MinimalWebConfiguration {
    }

}
