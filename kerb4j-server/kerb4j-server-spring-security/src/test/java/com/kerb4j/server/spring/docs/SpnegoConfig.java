/*
 * Copyright 2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.kerb4j.server.spring.docs;

import com.kerb4j.server.spring.KerberosAuthenticationProvider;
import com.kerb4j.server.spring.SpnegoAuthenticationProcessingFilter;
import com.kerb4j.server.spring.SpnegoAuthenticationProvider;
import com.kerb4j.server.spring.SpnegoEntryPoint;
import com.kerb4j.server.spring.jaas.sun.SunJaasKerberosTicketValidator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.FileSystemResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

//tag::snippetA[]
@Configuration
@EnableWebSecurity
public class SpnegoConfig {

    @Bean
    protected SecurityFilterChain configure(final HttpSecurity http) throws Exception {
        return http.exceptionHandling(e -> e.authenticationEntryPoint(spnegoEntryPoint()))
                .authorizeHttpRequests(a -> a
                        .requestMatchers("/", "/home").permitAll()
                        .anyRequest().authenticated())
                .formLogin(l -> l.loginPage("/login").permitAll())
                .logout(LogoutConfigurer::permitAll)
                .addFilterBefore(spnegoAuthenticationProcessingFilter(authManager()), BasicAuthenticationFilter.class)
                .build();
    }

    @Bean
    protected AuthenticationManager authManager() {
        return new ProviderManager(kerberosAuthenticationProvider(), kerberosServiceAuthenticationProvider());
    }

    @Bean
    public KerberosAuthenticationProvider kerberosAuthenticationProvider() {
        KerberosAuthenticationProvider provider = new KerberosAuthenticationProvider();
        provider.setUserDetailsService(dummyUserDetailsService());
        return provider;
    }

    @Bean
    public SpnegoEntryPoint spnegoEntryPoint() {
        return new SpnegoEntryPoint("/login");
    }

    @Bean
    public SpnegoAuthenticationProcessingFilter spnegoAuthenticationProcessingFilter(
            AuthenticationManager authenticationManager) {
        SpnegoAuthenticationProcessingFilter filter =
                new SpnegoAuthenticationProcessingFilter();
        filter.setAuthenticationManager(authenticationManager);
        return filter;
    }

    @Bean
    public SpnegoAuthenticationProvider kerberosServiceAuthenticationProvider() {
        SpnegoAuthenticationProvider provider =
                new SpnegoAuthenticationProvider();
        provider.setTicketValidator(sunJaasKerberosTicketValidator());
        provider.setUserDetailsService(dummyUserDetailsService());
        return provider;
    }

    @Bean
    public SunJaasKerberosTicketValidator sunJaasKerberosTicketValidator() {
        SunJaasKerberosTicketValidator ticketValidator =
                new SunJaasKerberosTicketValidator();
        ticketValidator.setServicePrincipal("HTTP/servicehost.example.org@EXAMPLE.ORG");
        ticketValidator.setKeyTabLocation(new FileSystemResource("/tmp/service.keytab"));
        //ticketValidator.setDebug(true);
        return ticketValidator;
    }

    @Bean
    public DummyUserDetailsService dummyUserDetailsService() {
        return new DummyUserDetailsService();
    }

}
//end::snippetA[]
