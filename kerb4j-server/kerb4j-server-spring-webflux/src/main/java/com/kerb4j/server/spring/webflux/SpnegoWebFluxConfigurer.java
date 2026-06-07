package com.kerb4j.server.spring.webflux;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.util.Assert;

/**
 * Utility class for configuring SPNEGO authentication in Spring WebFlux applications.
 * 
 * <p>This class provides helper methods to create and configure WebFlux authentication
 * components for SPNEGO/Kerberos authentication.</p>
 */
public final class SpnegoWebFluxConfigurer {

    private SpnegoWebFluxConfigurer() {
        // Utility class
    }

    /**
     * Creates an authentication web filter configured for SPNEGO authentication.
     * Basic authentication fallback is disabled by default.
     *
     * @param authenticationManager the authentication manager to use
     * @return configured authentication web filter
     */
    public static AuthenticationWebFilter createSpnegoAuthenticationWebFilter(
            AuthenticationManager authenticationManager) {
        return createSpnegoAuthenticationWebFilter(
                new ReactiveAuthenticationManagerAdapter(authenticationManager));
    }

    /**
     * Creates an authentication web filter configured for SPNEGO authentication.
     * Basic authentication fallback is disabled by default.
     *
     * @param reactiveAuthenticationManager the reactive authentication manager to use
     * @return configured authentication web filter
     */
    public static AuthenticationWebFilter createSpnegoAuthenticationWebFilter(
            ReactiveAuthenticationManager reactiveAuthenticationManager) {
        return createSpnegoAuthenticationWebFilter(reactiveAuthenticationManager, false);
    }

    /**
     * Creates an authentication web filter configured for SPNEGO authentication.
     *
     * @param reactiveAuthenticationManager the reactive authentication manager to use
     * @param supportBasicAuthentication    whether to support basic authentication fallback
     * @return configured authentication web filter
     */
    public static AuthenticationWebFilter createSpnegoAuthenticationWebFilter(
            ReactiveAuthenticationManager reactiveAuthenticationManager,
            boolean supportBasicAuthentication) {
        Assert.notNull(reactiveAuthenticationManager, "ReactiveAuthenticationManager cannot be null");
        
        SpnegoServerAuthenticationConverter converter = 
                new SpnegoServerAuthenticationConverter(supportBasicAuthentication);
        
        AuthenticationWebFilter authenticationWebFilter = new AuthenticationWebFilter(reactiveAuthenticationManager);
        authenticationWebFilter.setServerAuthenticationConverter(converter);
        
        // Match all requests by default
        authenticationWebFilter.setRequiresAuthenticationMatcher(ServerWebExchangeMatchers.anyExchange());
        
        return authenticationWebFilter;
    }

    /**
     * Creates an authentication web filter with custom matcher for SPNEGO authentication.
     *
     * @param reactiveAuthenticationManager the reactive authentication manager to use
     * @param matcher                       the server web exchange matcher
     * @param supportBasicAuthentication    whether to support basic authentication fallback
     * @return configured authentication web filter
     */
    public static AuthenticationWebFilter createSpnegoAuthenticationWebFilter(
            ReactiveAuthenticationManager reactiveAuthenticationManager,
            ServerWebExchangeMatcher matcher,
            boolean supportBasicAuthentication) {
        Assert.notNull(reactiveAuthenticationManager, "ReactiveAuthenticationManager cannot be null");
        Assert.notNull(matcher, "ServerWebExchangeMatcher cannot be null");
        
        SpnegoServerAuthenticationConverter converter = 
                new SpnegoServerAuthenticationConverter(supportBasicAuthentication);
        
        AuthenticationWebFilter authenticationWebFilter = new AuthenticationWebFilter(reactiveAuthenticationManager);
        authenticationWebFilter.setServerAuthenticationConverter(converter);
        authenticationWebFilter.setRequiresAuthenticationMatcher(matcher);
        
        return authenticationWebFilter;
    }
}