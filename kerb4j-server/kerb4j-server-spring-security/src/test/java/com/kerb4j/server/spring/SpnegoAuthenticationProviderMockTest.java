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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.*;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosKey;
import java.util.List;

import static org.mockito.Mockito.*;

/**
 * Test class for {@link SpnegoAuthenticationProvider}
 *
 * @author Mike Wiesner
 * @author Jeremy Stone
 * @since 1.0
 */
public class SpnegoAuthenticationProviderMockTest {

    private SpnegoAuthenticationProvider provider;
    private com.kerb4j.server.spring.KerberosTicketValidator ticketValidator;
    private AuthenticationUserDetailsService<SpnegoAuthenticationToken> extractGroupsUserDetailsService;
    private UserDetailsService userDetailsService;

    // data
    private static final byte[] TEST_TOKEN = "TestToken".getBytes();
    private static final byte[] RESPONSE_TOKEN = "ResponseToken".getBytes();
    private static final String TEST_USER = "Testuser@SPRINGSOURCE.ORG";

    private static final Subject subject = new Subject();
    private static final KerberosKey[] kerberosKeys = new KerberosKey[0];

    private static final SpnegoAuthenticationToken TICKET_VALIDATION = new SpnegoAuthenticationToken(TEST_TOKEN, TEST_USER, RESPONSE_TOKEN, subject, kerberosKeys);

    private static final List<GrantedAuthority> AUTHORITY_LIST = AuthorityUtils.createAuthorityList("ROLE_ADMIN");
    private static final UserDetails USER_DETAILS = new User(TEST_USER, "empty", true, true, true,true, AUTHORITY_LIST);
    private static final SpnegoRequestToken INPUT_TOKEN = new SpnegoRequestToken(TEST_TOKEN);

    @BeforeEach
    public void before() {
        // mocking
        this.ticketValidator = mock(KerberosTicketValidator.class);
        this.userDetailsService = mock(UserDetailsService.class);
        this.extractGroupsUserDetailsService = mock(AuthenticationUserDetailsService.class);

        this.provider = new SpnegoAuthenticationProvider();
        this.provider.setTicketValidator(this.ticketValidator);
        this.provider.setUserDetailsService(this.userDetailsService);
        this.provider.setExtractGroupsUserDetailsService(this.extractGroupsUserDetailsService);
    }

    @Test
    public void testEverythingWorks(){
        Authentication output = callProviderAndReturnUser(USER_DETAILS, INPUT_TOKEN);
        Assertions.assertNotNull(output);
        Assertions.assertEquals(TEST_USER, output.getName());
        Assertions.assertEquals(AUTHORITY_LIST, output.getAuthorities());
        Assertions.assertTrue(output.isAuthenticated());
        // assertEquals(USER_DETAILS, output.getPrincipal()); // TODO: principal should contain UserDetails object
    }

    @Test
    public void testAuthenticationDetailsPropagation(){
    	SpnegoRequestToken requestToken = new SpnegoRequestToken(TEST_TOKEN);
    	requestToken.setDetails("TestDetails");
        Authentication output = callProviderAndReturnUser(USER_DETAILS, requestToken);
        Assertions.assertNotNull(output);
        Assertions.assertEquals(requestToken.getDetails(), output.getDetails());
        Assertions.assertTrue(output.isAuthenticated());
    }

    @Test()
    public void testUserIsDisabled() {
        DisabledException exception = Assertions.assertThrows(DisabledException.class,
                () ->{
                    User disabledUser = new User(TEST_USER, "empty", false, true, true,true, AUTHORITY_LIST);
                    callProviderAndReturnUser(disabledUser, INPUT_TOKEN);
                });
        Assertions.assertNotNull(exception);
    }

    @Test()
    public void testUserAccountIsExpired() {
        AccountExpiredException exception = Assertions.assertThrows(AccountExpiredException.class, () -> {
            User expiredUser = new User(TEST_USER, "empty", true, false, true,true, AUTHORITY_LIST);
            callProviderAndReturnUser(expiredUser, INPUT_TOKEN);
        });
        Assertions.assertNotNull(exception);
    }

    @Test()
    public void testUserCredentialsExpired() {
        CredentialsExpiredException exception = Assertions.assertThrows(
                CredentialsExpiredException.class,
                () -> {
                    User credExpiredUser = new User(TEST_USER, "empty", true, true, false ,true, AUTHORITY_LIST);
                    callProviderAndReturnUser(credExpiredUser, INPUT_TOKEN);
                }
        );
        Assertions.assertNotNull(exception);
    }

    @Test()
    public void testUserAccountLockedCredentialsExpired() {
        LockedException exception = Assertions.assertThrows(
                LockedException.class,
                () -> {
                    User lockedUser = new User(TEST_USER, "empty", true, true, true ,false, AUTHORITY_LIST);
                    callProviderAndReturnUser(lockedUser, INPUT_TOKEN);
                }
        );
        Assertions.assertNotNull(exception);
    }

    @Test()
    public void testUsernameNotFound() {
        UsernameNotFoundException exception = Assertions.assertThrows(
                UsernameNotFoundException.class,
                () -> {
                    // stubbing
                    when(ticketValidator.validateTicket(TEST_TOKEN)).thenReturn(TICKET_VALIDATION);
                    when(userDetailsService.loadUserByUsername(TEST_USER)).thenThrow(new UsernameNotFoundException(""));

                    // testing
                    provider.authenticate(INPUT_TOKEN);
                }
        );
        Assertions.assertNotNull(exception);
    }


    @Test()
    public void testTicketValidationWrong(){
        BadCredentialsException exception = Assertions.assertThrows(
                BadCredentialsException.class, () -> {
                    // stubbing
                    when(ticketValidator.validateTicket(TEST_TOKEN)).thenThrow(new BadCredentialsException(""));

                    // testing
                    provider.authenticate(INPUT_TOKEN);
                }
        );
        Assertions.assertNotNull(exception);
    }

    private Authentication callProviderAndReturnUser(UserDetails userDetails, Authentication inputToken) {
        // stubbing
        when(ticketValidator.validateTicket(TEST_TOKEN)).thenReturn(TICKET_VALIDATION);
        when(userDetailsService.loadUserByUsername(TEST_USER)).thenReturn(userDetails);
        when(extractGroupsUserDetailsService.loadUserDetails(any(SpnegoAuthenticationToken.class))).thenReturn(userDetails);

        // testing
        return provider.authenticate(inputToken);
    }

}
