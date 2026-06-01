package com.kerb4j.server.spring.webflux;

import com.kerb4j.common.util.Constants;
import com.kerb4j.server.spring.SpnegoRequestToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

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
    void testDefaultBasicAuthIsDisabled() {
        SpnegoServerAuthenticationConverter defaultConverter = new SpnegoServerAuthenticationConverter();

        String credentials = "user:password";
        String base64Credentials = Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
        String basicHeader = Constants.BASIC_HEADER + " " + base64Credentials;

        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/test")
                        .header(Constants.AUTHZ_HEADER, basicHeader)
        );

        StepVerifier.create(defaultConverter.convert(exchange))
                .expectComplete()
                .verify();
    }

    @Test
    void testConvertWithNegotiateHeader() {
        byte[] tokenBytes = "TestToken".getBytes(StandardCharsets.UTF_8);
        String base64Token = Base64.getEncoder().encodeToString(tokenBytes);
        String negotiateHeader = Constants.NEGOTIATE_HEADER + " " + base64Token;

        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/test")
                        .header(Constants.AUTHZ_HEADER, negotiateHeader)
        );

        Mono<Authentication> result = converter.convert(exchange);

        StepVerifier.create(result)
                .assertNext(auth -> {
                    assertThat(auth).isInstanceOf(SpnegoRequestToken.class);
                    SpnegoRequestToken spnegoToken = (SpnegoRequestToken) auth;
                    assertThat(spnegoToken.getToken()).isEqualTo(tokenBytes);
                })
                .expectComplete()
                .verify();
    }

    @Test
    void testConvertWithCaseInsensitiveNegotiateHeader() {
        byte[] tokenBytes = "TestToken".getBytes(StandardCharsets.UTF_8);
        String base64Token = Base64.getEncoder().encodeToString(tokenBytes);
        String negotiateHeader = "negotiate " + base64Token;

        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/test")
                        .header(Constants.AUTHZ_HEADER, negotiateHeader)
        );

        StepVerifier.create(converter.convert(exchange))
                .assertNext(auth -> {
                    assertThat(auth).isInstanceOf(SpnegoRequestToken.class);
                    SpnegoRequestToken spnegoToken = (SpnegoRequestToken) auth;
                    assertThat(spnegoToken.getToken()).isEqualTo(tokenBytes);
                })
                .expectComplete()
                .verify();
    }

    @Test
    void testConvertWithBasicAuthenticationHeader() {
        converter.setSupportBasicAuthentication(true);

        String credentials = "user:password";
        String base64Credentials = Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
        String basicHeader = Constants.BASIC_HEADER + " " + base64Credentials;

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
        String credentials = "user:password";
        String base64Credentials = Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
        String basicHeader = Constants.BASIC_HEADER + " " + base64Credentials;

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
                        .header(Constants.AUTHZ_HEADER, "******")
        );

        Mono<Authentication> result = converter.convert(exchange);

        StepVerifier.create(result)
                .expectComplete()
                .verify();
    }

    @Test
    void testConvertWithMalformedNegotiateTokenReturnsBadCredentials() {
        String negotiateHeader = Constants.NEGOTIATE_HEADER + " not-valid-base64!!!";

        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/test")
                        .header(Constants.AUTHZ_HEADER, negotiateHeader)
        );

        StepVerifier.create(converter.convert(exchange))
                .expectError(BadCredentialsException.class)
                .verify();
    }

    @Test
    void testConvertWithMalformedBasicTokenReturnsBadCredentials() {
        converter.setSupportBasicAuthentication(true);
        String basicHeader = Constants.BASIC_HEADER + " not-valid-base64!!!";

        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/test")
                        .header(Constants.AUTHZ_HEADER, basicHeader)
        );

        StepVerifier.create(converter.convert(exchange))
                .expectError(BadCredentialsException.class)
                .verify();
    }

    @Test
    void testConvertWithBasicMissingDelimiterReturnsBadCredentials() {
        converter.setSupportBasicAuthentication(true);
        String base64 = Base64.getEncoder().encodeToString("usernameonly".getBytes(StandardCharsets.UTF_8));
        String basicHeader = Constants.BASIC_HEADER + " " + base64;

        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/test")
                        .header(Constants.AUTHZ_HEADER, basicHeader)
        );

        StepVerifier.create(converter.convert(exchange))
                .expectError(BadCredentialsException.class)
                .verify();
    }

    @Test
    void testConvertWithEmptyNegotiateTokenReturnsEmpty() {
        String negotiateHeader = Constants.NEGOTIATE_HEADER + "  ";

        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/test")
                        .header(Constants.AUTHZ_HEADER, negotiateHeader)
        );

        StepVerifier.create(converter.convert(exchange))
                .expectComplete()
                .verify();
    }
}
