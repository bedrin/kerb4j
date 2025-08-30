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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Sends back a request for a Negotiate Authentication to the browser for WebFlux applications.
 *
 * <p>This is the reactive WebFlux equivalent of {@link com.kerb4j.server.spring.SpnegoEntryPoint}.</p>
 *
 * @author Mike Wiesner (original SpnegoEntryPoint)
 * @author GitHub Copilot (WebFlux adaptation)
 * @see com.kerb4j.server.spring.SpnegoEntryPoint
 * @since 1.0
 */
public class SpnegoServerAuthenticationEntryPoint implements ServerAuthenticationEntryPoint {

    private static final Log LOG = LogFactory.getLog(SpnegoServerAuthenticationEntryPoint.class);

    private final String redirectUrl;

    private final boolean redirect;

    /**
     * Instantiates a new spnego server authentication entry point. Using this constructor
     * the EntryPoint will send back a request for a Negotiate Authentication to
     * the browser without providing a fallback mechanism for login.
     */
    public SpnegoServerAuthenticationEntryPoint() {
        this(null);
    }

    /**
     * Instantiates a new spnego server authentication entry point. This constructor enables
     * security configuration to use SPNEGO in combination with login form as fallback
     * for clients that do not support this kind of authentication.
     *
     * @param redirectUrl URL where the login page can be found. Should be
     *                    relative to the web-app context path (include a leading
     *                    {@code /}) and can't be absolute URL.
     */
    public SpnegoServerAuthenticationEntryPoint(String redirectUrl) {
        if (StringUtils.hasText(redirectUrl)) {
            Assert.isTrue(!isAbsoluteUrl(redirectUrl), "Redirect url specified must not be absolute");
            this.redirectUrl = redirectUrl;
            this.redirect = true;
        } else {
            this.redirectUrl = null;
            this.redirect = false;
        }
    }

    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException ex) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Add header WWW-Authenticate:Negotiate to " + exchange.getRequest().getURI() + 
                      ", redirect: " + (redirect ? redirectUrl : "no"));
        }
        
        exchange.getResponse().getHeaders().add("WWW-Authenticate", "Negotiate");
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);

        if (redirect) {
            exchange.getResponse().getHeaders().setLocation(exchange.getRequest().getURI().resolve(redirectUrl));
            return exchange.getResponse().setComplete();
        } else {
            return exchange.getResponse().setComplete();
        }
    }

    private boolean isAbsoluteUrl(String url) {
        return url.startsWith("http://") || url.startsWith("https://") || url.startsWith("//");
    }
}