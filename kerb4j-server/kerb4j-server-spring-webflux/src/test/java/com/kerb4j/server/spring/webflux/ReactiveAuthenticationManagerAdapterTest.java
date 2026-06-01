package com.kerb4j.server.spring.webflux;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
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
    void testAuthenticationFailurePropagatesError() {
        TestingAuthenticationToken inputAuth = new TestingAuthenticationToken("user", "wrongpassword");

        when(authenticationManager.authenticate(any(Authentication.class)))
                .thenThrow(new AuthenticationException("Authentication failed") {});

        StepVerifier.create(adapter.authenticate(inputAuth))
                .expectError(AuthenticationException.class)
                .verify();
    }

    @Test
    void testConstructorWithNullThrowsException() {
        assertThatThrownBy(() -> new ReactiveAuthenticationManagerAdapter(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("AuthenticationManager cannot be null");
    }
}
