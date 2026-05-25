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
package com.kerb4j.client;

import com.kerb4j.common.util.Constants;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.FileSystemResource;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.kerberos.authentication.KerberosServiceAuthenticationProvider;
import org.springframework.security.kerberos.authentication.KerberosServiceRequestToken;
import org.springframework.security.kerberos.authentication.sun.SunJaasKerberosTicketValidator;
import org.springframework.security.kerberos.web.authentication.SpnegoEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Configuration
@EnableWebSecurity
public class WebSecurityConfigSuccessHandler {

    @Value("${serverPrincipal}")
    private String serverPrincipal;

    @Value("${serverKeytab}")
    private String serverKeytab;

    @Bean
    protected SecurityFilterChain configure(final HttpSecurity http) throws Exception {
        return http
                .exceptionHandling(e -> e.authenticationEntryPoint(spnegoEntryPoint()))
                .authorizeHttpRequests(a -> a
                        .requestMatchers("/", "/home").permitAll()
                        .requestMatchers("/hello").hasRole("USER")
                        .anyRequest().authenticated())
                .addFilterBefore(spnegoAuthenticationProcessingFilter(authManager()), BasicAuthenticationFilter.class)
                .build();
    }

    @Bean
    protected AuthenticationManager authManager() {
        return new ProviderManager(kerberosServiceAuthenticationProvider());
    }

    @Bean
    public SpnegoEntryPoint spnegoEntryPoint() {
        return new SpnegoEntryPoint();
    }

    @Bean
    public SpringSecurity7SpnegoAuthenticationProcessingFilter spnegoAuthenticationProcessingFilter(AuthenticationManager authenticationManager) {
        SpringSecurity7SpnegoAuthenticationProcessingFilter filter = new SpringSecurity7SpnegoAuthenticationProcessingFilter();
        SpringSecurity7ResponseHeaderSettingKerberosAuthenticationSuccessHandler successHandler = new SpringSecurity7ResponseHeaderSettingKerberosAuthenticationSuccessHandler();
        filter.setSuccessHandler(successHandler);
        filter.setAuthenticationManager(authenticationManager);
        return filter;
    }

    @Bean
    public KerberosServiceAuthenticationProvider kerberosServiceAuthenticationProvider() {
        KerberosServiceAuthenticationProvider provider = new KerberosServiceAuthenticationProvider();
        provider.setTicketValidator(sunJaasKerberosTicketValidator());
        provider.setUserDetailsService(dummyUserDetailsService());
        return provider;
    }

    @Bean
    public SunJaasKerberosTicketValidator sunJaasKerberosTicketValidator() {
        SunJaasKerberosTicketValidator ticketValidator = new SunJaasKerberosTicketValidator();
        ticketValidator.setServicePrincipal(serverPrincipal);
        ticketValidator.setKeyTabLocation(new FileSystemResource(serverKeytab));
        ticketValidator.setDebug(true);
        return ticketValidator;
    }

    @Bean
    public DummyUserDetailsService dummyUserDetailsService() {
        return new DummyUserDetailsService();
    }

    static class DummyUserDetailsService implements UserDetailsService {

        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
            return new User(username, "notUsed", true, true, true, true,
                    AuthorityUtils.createAuthorityList("ROLE_USER"));
        }

    }

}

class SpringSecurity7SpnegoAuthenticationProcessingFilter extends OncePerRequestFilter {

        private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();
        private AuthenticationManager authenticationManager;
        private AuthenticationSuccessHandler successHandler;
        private AuthenticationFailureHandler failureHandler;
        private SessionAuthenticationStrategy sessionAuthenticationStrategy = new NullAuthenticatedSessionStrategy();
        private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
        private SecurityContextRepository securityContextRepository = new RequestAttributeSecurityContextRepository();
        private boolean skipIfAlreadyAuthenticated = true;

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
            if (skipIfAlreadyAuthenticated) {
                Authentication existingAuth = securityContextHolderStrategy.getContext().getAuthentication();
                if (existingAuth != null && existingAuth.isAuthenticated() && !(existingAuth instanceof AnonymousAuthenticationToken)) {
                    chain.doFilter(request, response);
                    return;
                }
            }

            String header = request.getHeader(Constants.AUTHZ_HEADER);
            if (header != null && header.startsWith(Constants.NEGOTIATE_HEADER)) {
                String base64Token = header.substring(header.indexOf(' ') + 1);
                byte[] kerberosTicket;
                try {
                    kerberosTicket = Base64.getDecoder().decode(base64Token.getBytes(StandardCharsets.UTF_8));
                } catch (IllegalArgumentException e) {
                    throw new AuthenticationServiceException("Negotiate Header was invalid: " + header, e);
                }

                KerberosServiceRequestToken authenticationRequest = new KerberosServiceRequestToken(kerberosTicket);
                authenticationRequest.setDetails(authenticationDetailsSource.buildDetails(request));

                Authentication authentication;
                try {
                    authentication = authenticationManager.authenticate(authenticationRequest);
                } catch (AuthenticationException e) {
                    securityContextHolderStrategy.clearContext();
                    if (failureHandler != null) {
                        failureHandler.onAuthenticationFailure(request, response, e);
                    } else {
                        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                        response.flushBuffer();
                    }
                    return;
                }

                sessionAuthenticationStrategy.onAuthentication(authentication, request, response);
                SecurityContext context = securityContextHolderStrategy.createEmptyContext();
                context.setAuthentication(authentication);
                securityContextHolderStrategy.setContext(context);
                securityContextRepository.saveContext(context, request, response);
                if (successHandler != null) {
                    successHandler.onAuthenticationSuccess(request, response, authentication);
                }
            }

            chain.doFilter(request, response);
        }

        @Override
        public void afterPropertiesSet() throws ServletException {
            super.afterPropertiesSet();
            if (authenticationManager == null) {
                throw new ServletException("authenticationManager must be specified");
            }
        }

        public void setAuthenticationManager(AuthenticationManager authenticationManager) {
            this.authenticationManager = authenticationManager;
        }

        public void setSuccessHandler(AuthenticationSuccessHandler successHandler) {
            this.successHandler = successHandler;
        }
}

class SpringSecurity7ResponseHeaderSettingKerberosAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

        @Override
        public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
            if (authentication instanceof KerberosServiceRequestToken kerberosToken && kerberosToken.hasResponseToken()) {
                response.setHeader("WWW-Authenticate", "Negotiate "
                        + Base64.getEncoder().encodeToString(kerberosToken.getTicketValidation().responseToken()));
            }
        }
}
