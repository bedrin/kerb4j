/*
 * Copyright 2009-2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.kerb4j.server.spring.integration;

import com.kerb4j.KerberosSecurityTestcase;
import com.kerb4j.MiniKdc;
import com.kerb4j.client.SpnegoClient;
import com.kerb4j.client.spring.KerberosRestTemplate;
import com.kerb4j.client.spring.SpnegoRestTemplate;
import com.kerb4j.server.spring.*;
import com.kerb4j.server.spring.jaas.sun.SunJaasKerberosTicketValidator;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.FileSystemResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.stereotype.Controller;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.annotation.Resource;
import java.io.File;

import static org.junit.Assert.assertEquals;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@SpringBootApplication
public class SpnegoAuthenticationProviderIntegrationTest extends KerberosSecurityTestcase {

    private static final String USER_NAME = "username";
    private static final String USER_PASSWORD = "password";

    private static final String SERVER_SPN = "HTTP/localhost";

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @LocalServerPort
    private int port;

    private File keytabFile;

    @Resource
    private SunJaasKerberosTicketValidator sunJaasKerberosTicketValidator;

    @Before
    public void setupKDC() throws Exception {
        // mocking
        MiniKdc kdc = getKdc();

        File keytabFile = folder.newFile("serverKeyTab.keytab");

        kdc.createPrincipal(keytabFile, SERVER_SPN);

        sunJaasKerberosTicketValidator.setServicePrincipal(SERVER_SPN);
        sunJaasKerberosTicketValidator.setKeyTabLocation(new FileSystemResource(keytabFile));
        sunJaasKerberosTicketValidator.afterPropertiesSet();

        kdc.createPrincipal(USER_NAME, USER_PASSWORD);

    }

    @Test
    public void testContextLoaded() {

    }

    @Test
    public void testSpnegoAuthentication() {

        SpnegoClient spnegoClient = SpnegoClient.loginWithUsernamePassword(USER_NAME, USER_PASSWORD);
        SpnegoRestTemplate restTemplate = new SpnegoRestTemplate(spnegoClient);

        String response = restTemplate.getForObject("http://localhost:" + port + "/hello", String.class);

        assertEquals("hello", response);

    }

    @Test
    public void testKerberosAuthentication() {

        KerberosRestTemplate restTemplate = new KerberosRestTemplate(USER_NAME, USER_PASSWORD);

        String response = restTemplate.getForObject("http://localhost:" + port + "/hello", String.class);

        assertEquals("hello", response);

    }

    @Configuration
    @EnableWebSecurity
    public static class WebSecurityConfigSuccessHandler extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .exceptionHandling().authenticationEntryPoint(spnegoEntryPoint()).and()
                    .authorizeRequests()
                    .antMatchers("/", "/home").permitAll()
                    .antMatchers("/hello").access("hasRole('ROLE_USER')")
                    .anyRequest().authenticated()
                    .and()

                    .httpBasic().and()

                    .addFilterBefore(spnegoAuthenticationProcessingFilter(authenticationManagerBean()), BasicAuthenticationFilter.class);
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.authenticationProvider(kerberosServiceAuthenticationProvider());
        }

        @Bean
        public SpnegoEntryPoint spnegoEntryPoint() {
            return new SpnegoEntryPoint();
        }

        @Bean
        public SpnegoAuthenticationProcessingFilter spnegoAuthenticationProcessingFilter(
                AuthenticationManager authenticationManager) {
            SpnegoAuthenticationProcessingFilter filter = new SpnegoAuthenticationProcessingFilter();

            SpnegoMutualAuthenticationHandler successHandler = new SpnegoMutualAuthenticationHandler();
            filter.setAuthenticationSuccessHandler(successHandler);

            filter.setAuthenticationManager(authenticationManager);
            return filter;
        }

        @Bean
        public SpnegoAuthenticationProvider kerberosServiceAuthenticationProvider() {
            SpnegoAuthenticationProvider provider = new SpnegoAuthenticationProvider();
            provider.setTicketValidator(sunJaasKerberosTicketValidator());
            provider.setExtractGroupsUserDetailsService(dummyUserDetailsService());
            provider.setServerSpn(SERVER_SPN);
            return provider;
        }

        @Bean
        public SunJaasKerberosTicketValidator sunJaasKerberosTicketValidator() {
            SunJaasKerberosTicketValidator sunJaasKerberosTicketValidator = new SunJaasKerberosTicketValidator();
            sunJaasKerberosTicketValidator.setServicePrincipal("");
            sunJaasKerberosTicketValidator.setKeyTabLocation(new FileSystemResource("/tmp/some/not/used/path"));
            return sunJaasKerberosTicketValidator;
        }

        @Bean
        public DummyUserDetailsService dummyUserDetailsService() {
            return new DummyUserDetailsService();
        }

        static class DummyUserDetailsService implements AuthenticationUserDetailsService<SpnegoAuthenticationToken> {

            @Override
            public UserDetails loadUserDetails(SpnegoAuthenticationToken token) throws UsernameNotFoundException {
                return new User(token.username(), "notUsed", true, true, true, true,
                        AuthorityUtils.createAuthorityList("ROLE_USER"));
            }

        }

    }

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

        @RequestMapping(method = RequestMethod.GET, value = "/hello")
        @ResponseBody
        public String hello() {
            return "hello";
        }

    }

}
