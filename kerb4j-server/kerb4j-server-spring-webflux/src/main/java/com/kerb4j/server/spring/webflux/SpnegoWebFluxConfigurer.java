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

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;

/**
 * Utility class for configuring SPNEGO authentication in Spring WebFlux applications.
 * 
 * <p>This class provides helper methods to create and configure WebFlux authentication
 * components for SPNEGO/Kerberos authentication.</p>
 *
 * @author GitHub Copilot
 * @since 1.0
 */
public class SpnegoWebFluxConfigurer {

    /**
     * Creates an authentication web filter configured for SPNEGO authentication.
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
     *
     * @param reactiveAuthenticationManager the reactive authentication manager to use
     * @return configured authentication web filter
     */
    public static AuthenticationWebFilter createSpnegoAuthenticationWebFilter(
            ReactiveAuthenticationManager reactiveAuthenticationManager) {
        return createSpnegoAuthenticationWebFilter(reactiveAuthenticationManager, true);
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
        
        SpnegoServerAuthenticationConverter converter = 
                new SpnegoServerAuthenticationConverter(supportBasicAuthentication);
        
        AuthenticationWebFilter authenticationWebFilter = new AuthenticationWebFilter(reactiveAuthenticationManager);
        authenticationWebFilter.setServerAuthenticationConverter(converter);
        authenticationWebFilter.setRequiresAuthenticationMatcher(matcher);
        
        return authenticationWebFilter;
    }
}