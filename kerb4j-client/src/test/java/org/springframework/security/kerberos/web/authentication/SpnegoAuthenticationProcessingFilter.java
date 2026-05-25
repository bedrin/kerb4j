package org.springframework.security.kerberos.web.authentication;

import com.kerb4j.common.util.Constants;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.kerberos.authentication.KerberosServiceRequestToken;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
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

public class SpnegoAuthenticationProcessingFilter extends OncePerRequestFilter {

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

    public void setFailureHandler(AuthenticationFailureHandler failureHandler) {
        this.failureHandler = failureHandler;
    }

    public void setSkipIfAlreadyAuthenticated(boolean skipIfAlreadyAuthenticated) {
        this.skipIfAlreadyAuthenticated = skipIfAlreadyAuthenticated;
    }

    public void setSessionAuthenticationStrategy(SessionAuthenticationStrategy sessionAuthenticationStrategy) {
        this.sessionAuthenticationStrategy = sessionAuthenticationStrategy;
    }

    public void setSecurityContextRepository(SecurityContextRepository securityContextRepository) {
        this.securityContextRepository = securityContextRepository;
    }
}
