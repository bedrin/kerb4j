/*
 * Copyright 2002-2015 the original author or authors.
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
package com.kerb4j.server.spring.webflux;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Test class for {@link ReactiveAuthenticationManagerAdapter}
 *
 * @author GitHub Copilot
 * @since 1.0
 */
class ReactiveAuthenticationManagerAdapterTest {

    private AuthenticationManager authenticationManager;
    private ReactiveAuthenticationManagerAdapter adapter;

    @BeforeEach
    void setUp() {
        authenticationManager = mock(AuthenticationManager.class);
        adapter = new ReactiveAuthenticationManagerAdapter(authenticationManager);
    }

    @Test
    void testSuccessfulAuthentication() {
        TestingAuthenticationToken inputAuth = new TestingAuthenticationToken("user", "password");
        TestingAuthenticationToken outputAuth = new TestingAuthenticationToken("user", "password", "ROLE_USER");
        
        when(authenticationManager.authenticate(any(Authentication.class))).thenReturn(outputAuth);

        StepVerifier.create(adapter.authenticate(inputAuth))
                .assertNext(auth -> {
                    assertThat(auth).isEqualTo(outputAuth);
                    assertThat(auth.isAuthenticated()).isTrue();
                })
                .expectComplete()
                .verify();
    }

    @Test
    void testAuthenticationFailure() {
        TestingAuthenticationToken inputAuth = new TestingAuthenticationToken("user", "wrongpassword");
        
        when(authenticationManager.authenticate(any(Authentication.class)))
                .thenThrow(new AuthenticationException("Authentication failed") {});

        StepVerifier.create(adapter.authenticate(inputAuth))
                .expectError(AuthenticationException.class)
                .verify();
    }

    @Test
    void testConstructorWithNullThrowsException() {
        try {
            new ReactiveAuthenticationManagerAdapter(null);
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage()).contains("AuthenticationManager cannot be null");
        }
    }
}