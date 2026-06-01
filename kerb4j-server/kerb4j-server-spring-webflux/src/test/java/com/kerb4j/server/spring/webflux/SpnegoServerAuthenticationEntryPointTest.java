package com.kerb4j.server.spring.webflux;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.AuthenticationException;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Test class for {@link SpnegoServerAuthenticationEntryPoint}
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
    void testEntryPointWithRedirectUses303() {
        String redirectUrl = "/login";
        SpnegoServerAuthenticationEntryPoint entryPoint = new SpnegoServerAuthenticationEntryPoint(redirectUrl);
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/test"));

        StepVerifier.create(entryPoint.commence(exchange, new AuthenticationException("Test") {}))
                .expectComplete()
                .verify();

        assertThat(exchange.getResponse().getHeaders().getFirst("WWW-Authenticate")).isEqualTo("Negotiate");
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.SEE_OTHER);
        assertThat(exchange.getResponse().getHeaders().getLocation()).isNotNull();
        assertThat(exchange.getResponse().getHeaders().getLocation().getPath()).endsWith("/login");
    }

    @Test
    void testEntryPointWithRedirectPreservesContextPath() {
        SpnegoServerAuthenticationEntryPoint entryPoint = new SpnegoServerAuthenticationEntryPoint("/login");
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/app/test")
                        .contextPath("/app")
        );

        StepVerifier.create(entryPoint.commence(exchange, new AuthenticationException("Test") {}))
                .expectComplete()
                .verify();

        assertThat(exchange.getResponse().getHeaders().getFirst("WWW-Authenticate")).isEqualTo("Negotiate");
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.SEE_OTHER);
        assertThat(exchange.getResponse().getHeaders().getLocation()).isNotNull();
        assertThat(exchange.getResponse().getHeaders().getLocation().getPath()).isEqualTo("/app/login");
    }

    @Test
    void testEntryPointWithAbsoluteUrlThrowsException() {
        assertThatThrownBy(() -> new SpnegoServerAuthenticationEntryPoint("http://example.com/login"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Redirect url specified must not be absolute");
    }

    @Test
    void testEntryPointWithRedirectUrlWithoutLeadingSlashThrowsException() {
        assertThatThrownBy(() -> new SpnegoServerAuthenticationEntryPoint("login"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Redirect url specified must start with /");
    }

    @Test
    void testEntryPointWithNullRedirectUrlBehavesLikeNoRedirect() {
        SpnegoServerAuthenticationEntryPoint entryPoint = new SpnegoServerAuthenticationEntryPoint(null);
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/test"));

        StepVerifier.create(entryPoint.commence(exchange, new AuthenticationException("Test") {}))
                .expectComplete()
                .verify();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(exchange.getResponse().getHeaders().getLocation()).isNull();
    }

    @Test
    void testEntryPointWithEmptyStringRedirectUrlBehavesLikeNoRedirect() {
        SpnegoServerAuthenticationEntryPoint entryPoint = new SpnegoServerAuthenticationEntryPoint("");
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/test"));

        StepVerifier.create(entryPoint.commence(exchange, new AuthenticationException("Test") {}))
                .expectComplete()
                .verify();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(exchange.getResponse().getHeaders().getLocation()).isNull();
    }
}
