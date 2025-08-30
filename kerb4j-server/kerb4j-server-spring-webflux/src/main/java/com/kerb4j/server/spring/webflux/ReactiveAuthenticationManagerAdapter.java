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

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Reactive wrapper for {@link AuthenticationManager} to be used in WebFlux applications.
 * 
 * <p>This allows existing {@link AuthenticationManager} implementations (like those used
 * for SPNEGO authentication) to be used in reactive WebFlux applications by wrapping
 * the blocking authentication calls.</p>
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