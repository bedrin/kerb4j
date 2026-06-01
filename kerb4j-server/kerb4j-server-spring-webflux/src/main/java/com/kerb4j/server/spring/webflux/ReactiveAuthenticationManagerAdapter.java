package com.kerb4j.server.spring.webflux;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Reactive wrapper for {@link AuthenticationManager} to be used in WebFlux applications.
 *
 * <p>This allows existing blocking {@link AuthenticationManager} implementations (such as
 * the Kerb4J SPNEGO authentication provider) to be used in reactive WebFlux applications.
 * The blocking authentication call is offloaded to the
 * {@link reactor.core.scheduler.Schedulers#boundedElastic() boundedElastic} scheduler,
 * meaning that authentication work is <strong>not</strong> fully non-blocking — it runs
 * on a thread-pool-backed scheduler designed for blocking I/O.</p>
 *
 * @author GitHub Copilot
 * @since 1.0
 */
public class ReactiveAuthenticationManagerAdapter implements ReactiveAuthenticationManager {

    private final AuthenticationManager authenticationManager;

    /**
     * Creates a new reactive authentication manager adapter.
     *
     * @param authenticationManager the underlying authentication manager to adapt
     */
    public ReactiveAuthenticationManagerAdapter(AuthenticationManager authenticationManager) {
        Assert.notNull(authenticationManager, "AuthenticationManager cannot be null");
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        return Mono.fromCallable(() -> authenticationManager.authenticate(authentication))
                .subscribeOn(Schedulers.boundedElastic());
    }
}