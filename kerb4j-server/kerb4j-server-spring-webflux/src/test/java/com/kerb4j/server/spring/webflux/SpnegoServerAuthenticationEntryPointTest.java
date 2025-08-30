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
package com.kerb4j.server.spring.webflux;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.authentication.ServerAuthenticationEntryPointFailureHandler;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test class for {@link SpnegoServerAuthenticationEntryPoint}
 *
 * @author GitHub Copilot
 * @since 1.0
 */
class SpnegoServerAuthenticationEntryPointTest {

    @Test
    void testEntryPointOk() {
        SpnegoServerAuthenticationEntryPoint entryPoint = new SpnegoServerAuthenticationEntryPoint();
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/test"));
        
        StepVerifier.create(entryPoint.commence(exchange, new AuthenticationException("Test") {}))
                .expectComplete()
                .verify();

        assertThat(exchange.getResponse().getHeaders().getFirst("WWW-Authenticate")).isEqualTo("Negotiate");
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void testEntryPointWithRedirect() {
        String redirectUrl = "/login";
        SpnegoServerAuthenticationEntryPoint entryPoint = new SpnegoServerAuthenticationEntryPoint(redirectUrl);
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/test"));
        
        StepVerifier.create(entryPoint.commence(exchange, new AuthenticationException("Test") {}))
                .expectComplete()
                .verify();

        assertThat(exchange.getResponse().getHeaders().getFirst("WWW-Authenticate")).isEqualTo("Negotiate");
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(exchange.getResponse().getHeaders().getLocation()).isNotNull();
    }

    @Test
    void testEntryPointWithAbsoluteUrlThrowsException() {
        try {
            new SpnegoServerAuthenticationEntryPoint("http://example.com/login");
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage()).contains("Redirect url specified must not be absolute");
        }
    }
}