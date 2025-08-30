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

import com.kerb4j.common.util.Constants;
import com.kerb4j.common.util.base64.Base64Codec;
import com.kerb4j.server.spring.SpnegoRequestToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test class for {@link SpnegoServerAuthenticationConverter}
 *
 * @author GitHub Copilot
 * @since 1.0
 */
class SpnegoServerAuthenticationConverterTest {

    private SpnegoServerAuthenticationConverter converter;

    @BeforeEach
    void setUp() {
        converter = new SpnegoServerAuthenticationConverter();
    }

    @Test
    void testConvertWithNegotiateHeader() {
        String testToken = "VGVzdFRva2Vu"; // Base64 for "TestToken"
        String negotiateHeader = Constants.NEGOTIATE_HEADER + testToken;
        
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/test")
                        .header(Constants.AUTHZ_HEADER, negotiateHeader)
        );

        Mono<Authentication> result = converter.convert(exchange);

        StepVerifier.create(result)
                .assertNext(auth -> {
                    assertThat(auth).isInstanceOf(SpnegoRequestToken.class);
                    SpnegoRequestToken spnegoToken = (SpnegoRequestToken) auth;
                    assertThat(spnegoToken.getToken()).isNotNull();
                })
                .expectComplete()
                .verify();
    }

    @Test
    void testConvertWithBasicAuthenticationHeader() {
        String credentials = "user:password";
        String base64Credentials = new String(Base64Codec.encode(credentials.getBytes(StandardCharsets.UTF_8)));
        String basicHeader = Constants.BASIC_HEADER + base64Credentials;
        
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/test")
                        .header(Constants.AUTHZ_HEADER, basicHeader)
        );

        Mono<Authentication> result = converter.convert(exchange);

        StepVerifier.create(result)
                .assertNext(auth -> {
                    assertThat(auth).isInstanceOf(UsernamePasswordAuthenticationToken.class);
                    assertThat(auth.getName()).isEqualTo("user");
                    assertThat(auth.getCredentials()).isEqualTo("password");
                })
                .expectComplete()
                .verify();
    }

    @Test
    void testConvertWithBasicAuthenticationDisabled() {
        converter.setSupportBasicAuthentication(false);
        
        String credentials = "user:password";
        String base64Credentials = new String(Base64Codec.encode(credentials.getBytes(StandardCharsets.UTF_8)));
        String basicHeader = Constants.BASIC_HEADER + base64Credentials;
        
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/test")
                        .header(Constants.AUTHZ_HEADER, basicHeader)
        );

        Mono<Authentication> result = converter.convert(exchange);

        StepVerifier.create(result)
                .expectComplete()
                .verify();
    }

    @Test
    void testConvertWithNoAuthorizationHeader() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/test"));

        Mono<Authentication> result = converter.convert(exchange);

        StepVerifier.create(result)
                .expectComplete()
                .verify();
    }

    @Test
    void testConvertWithUnsupportedAuthorizationHeader() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/test")
                        .header(Constants.AUTHZ_HEADER, "Bearer token")
        );

        Mono<Authentication> result = converter.convert(exchange);

        StepVerifier.create(result)
                .expectComplete()
                .verify();
    }
}