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

import com.kerb4j.server.spring.SpnegoAuthenticationProvider;
import com.kerb4j.server.spring.jaas.sun.SunJaasKerberosTicketValidator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.FileSystemResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;

/**
 * Example WebFlux security configuration using SPNEGO authentication.
 * 
 * <p>This configuration demonstrates how to set up Kerberos/SPNEGO authentication
 * in a Spring WebFlux application using the kerb4j WebFlux components.</p>
 *
 * @author GitHub Copilot
 * @since 1.0
 */
@Configuration
@EnableWebFluxSecurity
public class WebFluxSecurityConfig {

    @Value("${serverPrincipal:HTTP/localhost@EXAMPLE.COM}")
    private String serverPrincipal;

    @Value("${serverKeytab:/path/to/server.keytab}")
    private String serverKeytab;

    @Bean
    public SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http) {
        return http
                .exceptionHandling(e -> e.authenticationEntryPoint(spnegoServerAuthenticationEntryPoint()))
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/").permitAll()
                        .pathMatchers("/hello").hasRole("USER")
                        .anyExchange().permitAll())
                .addFilterBefore(spnegoAuthenticationWebFilter(), SecurityWebFiltersOrder.AUTHENTICATION)
                .build();
    }

    @Bean
    public AuthenticationWebFilter spnegoAuthenticationWebFilter() {
        return SpnegoWebFluxConfigurer.createSpnegoAuthenticationWebFilter(
                new ReactiveAuthenticationManagerAdapter(authManager()));
    }

    @Bean
    public AuthenticationManager authManager() {
        return new ProviderManager(kerberosServiceAuthenticationProvider());
    }

    @Bean
    public SpnegoServerAuthenticationEntryPoint spnegoServerAuthenticationEntryPoint() {
        return new SpnegoServerAuthenticationEntryPoint();
    }

    @Bean
    public SpnegoAuthenticationProvider kerberosServiceAuthenticationProvider() {
        SpnegoAuthenticationProvider provider = new SpnegoAuthenticationProvider();
        provider.setTicketValidator(sunJaasKerberosTicketValidator());
        provider.setUserDetailsService(dummyUserDetailsService());
        return provider;
    }

    @Bean
    public SunJaasKerberosTicketValidator sunJaasKerberosTicketValidator() {
        SunJaasKerberosTicketValidator ticketValidator = new SunJaasKerberosTicketValidator();
        ticketValidator.setServicePrincipal(serverPrincipal);
        ticketValidator.setKeyTabLocation(new FileSystemResource(serverKeytab));
        return ticketValidator;
    }

    @Bean
    public DummyUserDetailsService dummyUserDetailsService() {
        return new DummyUserDetailsService();
    }

    static class DummyUserDetailsService implements UserDetailsService {

        @Override
        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
            return new User(username, "notUsed", true, true, true, true,
                    AuthorityUtils.createAuthorityList("ROLE_USER"));
        }
    }
}