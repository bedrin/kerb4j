package com.kerb4j.server.spring.webflux;

import com.kerb4j.common.util.Constants;
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
 * <p>This is the reactive WebFlux equivalent of Kerb4J's servlet SPNEGO entry point.</p>
 *
 * @author Mike Wiesner (original SpnegoEntryPoint)
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
            Assert.isTrue(redirectUrl.startsWith("/"), "Redirect url specified must start with /");
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

        exchange.getResponse().getHeaders().add(Constants.AUTHN_HEADER, Constants.NEGOTIATE_HEADER);

        if (redirect) {
            exchange.getResponse().setStatusCode(HttpStatus.SEE_OTHER);
            exchange.getResponse().getHeaders().setLocation(createRedirectUri(exchange));
        } else {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        }

        return exchange.getResponse().setComplete();
    }

    private java.net.URI createRedirectUri(ServerWebExchange exchange) {
        String contextPath = exchange.getRequest().getPath().contextPath().value();
        return exchange.getRequest().getURI().resolve(contextPath + redirectUrl);
    }

    private boolean isAbsoluteUrl(String url) {
        return url.startsWith("http://") || url.startsWith("https://") || url.startsWith("//");
    }
}