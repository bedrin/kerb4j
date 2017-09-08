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
package com.kerb4j.server.spring;

import com.kerb4j.client.SpnegoClient;
import com.kerb4j.server.spring.KerberosAuthenticationProvider;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.rule.PowerMockRule;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import javax.security.auth.login.LoginException;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.*;

/**
 * Test class for {@link com.kerb4j.server.spring.KerberosAuthenticationProvider}
 *
 * @author Mike Wiesner
 * @since 1.0
 */
@PrepareForTest(SpnegoClient.class)
public class KerberosAuthenticationProviderTest {

    @Rule
    public PowerMockRule rule = new PowerMockRule();

    private com.kerb4j.server.spring.KerberosAuthenticationProvider provider;
    private UserDetailsService userDetailsService;

    private static final String TEST_USER = "Testuser@SPRINGSOURCE.ORG";
    private static final String TEST_PASSWORD = "password";
    private static final UsernamePasswordAuthenticationToken INPUT_TOKEN = new UsernamePasswordAuthenticationToken(TEST_USER, TEST_PASSWORD);
    private static final List<GrantedAuthority> AUTHORITY_LIST = AuthorityUtils.createAuthorityList("ROLE_ADMIN");
    private static final UserDetails USER_DETAILS = new User(TEST_USER, "empty", true, true, true,true, AUTHORITY_LIST);

    @Before
    public void before() throws LoginException {
        // mocking
        PowerMockito.mockStatic(SpnegoClient.class);

        this.userDetailsService = mock(UserDetailsService.class);
        this.provider = new KerberosAuthenticationProvider();
        this.provider.setUserDetailsService(userDetailsService);
    }

    @Test
    public void testLoginOk() throws Exception {
        AtomicInteger counter = new AtomicInteger();

        when(userDetailsService.loadUserByUsername(TEST_USER)).thenReturn(USER_DETAILS);
        when(SpnegoClient.loginWithUsernamePassword(anyString(), anyString()))
                .then(invocationOnMock -> {
                    counter.incrementAndGet();
                    return null;
                });

        Authentication authenticate = provider.authenticate(INPUT_TOKEN);

        assertEquals(1, counter.get());

        assertNotNull(authenticate);
        assertEquals(TEST_USER, authenticate.getName());
        assertEquals(USER_DETAILS, authenticate.getPrincipal());
        assertEquals(TEST_PASSWORD, authenticate.getCredentials());
        assertEquals(AUTHORITY_LIST, authenticate.getAuthorities());

    }
}
