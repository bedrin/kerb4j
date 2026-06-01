package com.kerb4j.server.spring;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.*;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.context.SecurityContextRepository;

import java.io.IOException;
import java.util.function.Supplier;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Test class for {@link SpnegoAuthenticationProcessingFilter}
 *
 * @author Mike Wiesner
 * @author Jeremy Stone
 */
public class SpnegoAuthenticationProcessingFilterTest {

    // data
    private static final byte[] TEST_TOKEN = "TestToken".getBytes();
    private static final String TEST_TOKEN_BASE64 = "VGVzdFRva2Vu";
    private static final String HEADER = "Authorization";
    private static final String TOKEN_PREFIX_NEG = "Negotiate ";
    private static final String TOKEN_PREFIX_KERB = "Kerberos ";
    //private static SpnegoAuthenticationToken UNUSED_TICKET_VALIDATION = mock(SpnegoAuthenticationToken.class);
    private SpnegoAuthenticationProcessingFilter filter;
    private AuthenticationManager authenticationManager;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private FilterChain chain;
    private AuthenticationSuccessHandler successHandler;
    private AuthenticationFailureHandler failureHandler;
    private WebAuthenticationDetailsSource detailsSource;
    private SecurityContextHolderStrategy securityContextHolderStrategy;

    @BeforeEach
    public void before() throws Exception {
        // mocking
        authenticationManager = mock(AuthenticationManager.class);
        detailsSource = new WebAuthenticationDetailsSource();
        filter = new SpnegoAuthenticationProcessingFilter();
        filter.setAuthenticationManager(authenticationManager);
        // Use a dedicated strategy instance so tests assert against the same strategy the filter uses.
        securityContextHolderStrategy = new TestSecurityContextHolderStrategy();
        filter.setSecurityContextHolderStrategy(securityContextHolderStrategy);
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        chain = mock(FilterChain.class);
        filter.afterPropertiesSet();
    }

    @Test
    void testEverythingWorks() throws Exception {
        everythingWorks(TOKEN_PREFIX_NEG);
    }

    @Test
    @Disabled("spring-security-kerberos used to support \"Kerberos\" scheme. Is it a valid use case?")
    void testEverythingWorks_Kerberos() throws Exception {
        everythingWorks(TOKEN_PREFIX_KERB);
    }

    @Test
    void testEverythingWorksWithHandlers() throws Exception {
        everythingWorksWithHandlers(TOKEN_PREFIX_NEG);
    }

    @Test
    @Disabled("spring-security-kerberos used to support \"Kerberos\" scheme. Is it a valid use case?")
    void testEverythingWorksWithHandlers_Kerberos() throws Exception {
        everythingWorksWithHandlers(TOKEN_PREFIX_KERB);
    }

    private void everythingWorksWithHandlers(String tokenPrefix) throws Exception {
        Authentication AUTHENTICATION = new SpnegoRequestToken(TEST_TOKEN);
        createHandler();
        everythingWorks(tokenPrefix);
        verify(successHandler).onAuthenticationSuccess(request, response, AUTHENTICATION);
        verify(failureHandler, never()).onAuthenticationFailure(any(HttpServletRequest.class),
                any(HttpServletResponse.class), any(AuthenticationException.class));
    }

    private void everythingWorks(String tokenPrefix) throws IOException,
            ServletException {
        Authentication AUTHENTICATION = new SpnegoRequestToken(TEST_TOKEN);
        // stubbing
        when(request.getHeader(HEADER)).thenReturn(tokenPrefix + TEST_TOKEN_BASE64);
        SpnegoRequestToken requestToken = new SpnegoRequestToken(TEST_TOKEN);
        requestToken.setDetails(detailsSource.buildDetails(request));
        when(authenticationManager.authenticate(requestToken)).thenReturn(AUTHENTICATION);

        // testing
        filter.doFilter(request, response, chain);
        verify(chain).doFilter(request, response);
        Assertions.assertEquals(AUTHENTICATION, currentAuthentication());
    }

    @Test
    void testNoHeader() throws Exception {
        filter.doFilter(request, response, chain);
        // If the header is not present, the filter is not allowed to call
        // authenticate()
        verify(authenticationManager, never()).authenticate(any(Authentication.class));
        // chain should go on
        verify(chain).doFilter(request, response);
        Assertions.assertNull(currentAuthentication());
    }

    @Test
    void testAuthenticationFails() throws Exception {
        authenticationFails();
        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }

    @Test
    void testAuthenticationFailsWithHandlers() throws Exception {
        createHandler();
        BadCredentialsException BCE = authenticationFails();
        verify(failureHandler).onAuthenticationFailure(request, response, BCE);
        verify(successHandler, never()).onAuthenticationSuccess(any(HttpServletRequest.class),
                any(HttpServletResponse.class), any(Authentication.class));
        verify(response, never()).setStatus(anyInt());
    }

    @Test
    void testAlreadyAuthenticated() throws Exception {
        try {
            Authentication existingAuth = new UsernamePasswordAuthenticationToken("mike", "mike",
                    AuthorityUtils.createAuthorityList("ROLE_TEST"));
            setCurrentAuthentication(existingAuth);
            when(request.getHeader(HEADER)).thenReturn(TOKEN_PREFIX_NEG + TEST_TOKEN_BASE64);
            filter.doFilter(request, response, chain);
            verify(authenticationManager, never()).authenticate(any(Authentication.class));
        } finally {
            securityContextHolderStrategy.clearContext();
        }
    }

    @Test
    void testAlreadyAuthenticatedWithNotAuthenticatedToken()
            throws Exception {
        try {
            // this token is not authenticated yet!
            Authentication existingAuth = new UsernamePasswordAuthenticationToken("mike", "mike");
            setCurrentAuthentication(existingAuth);
            everythingWorks(TOKEN_PREFIX_NEG);
        } finally {
            securityContextHolderStrategy.clearContext();
        }
    }

    @Test
    void testAlreadyAuthenticatedWithAnonymousToken() throws Exception {
        try {
            Authentication existingAuth = new AnonymousAuthenticationToken("test", "mike",
                    AuthorityUtils.createAuthorityList("ROLE_TEST"));
            setCurrentAuthentication(existingAuth);
            everythingWorks(TOKEN_PREFIX_NEG);
        } finally {
            securityContextHolderStrategy.clearContext();
        }
    }

    @Test
    void testAlreadyAuthenticatedNotActive() throws Exception {
        try {
            Authentication existingAuth = new UsernamePasswordAuthenticationToken("mike", "mike",
                    AuthorityUtils.createAuthorityList("ROLE_TEST"));
            setCurrentAuthentication(existingAuth);
            filter.setSkipIfAlreadyAuthenticated(false);
            everythingWorks(TOKEN_PREFIX_NEG);
        } finally {
            securityContextHolderStrategy.clearContext();
        }
    }

    @Test
    void testConfiguredSecurityContextRepositoryIsUsed() throws Exception {
        Authentication authentication = new SpnegoRequestToken(TEST_TOKEN);
        SecurityContextRepository securityContextRepository = mock(SecurityContextRepository.class);
        filter.setSecurityContextRepository(securityContextRepository);
        when(request.getHeader(HEADER)).thenReturn(TOKEN_PREFIX_NEG + TEST_TOKEN_BASE64);
        SpnegoRequestToken requestToken = new SpnegoRequestToken(TEST_TOKEN);
        requestToken.setDetails(detailsSource.buildDetails(request));
        when(authenticationManager.authenticate(requestToken)).thenReturn(authentication);

        filter.doFilter(request, response, chain);

        verify(securityContextRepository).saveContext(any(SecurityContext.class), eq(request), eq(response));
    }

    private BadCredentialsException authenticationFails() throws IOException, ServletException {

        BadCredentialsException BCE = new BadCredentialsException("");

        // stubbing
        when(request.getHeader(HEADER)).thenReturn(TOKEN_PREFIX_NEG + TEST_TOKEN_BASE64);
        when(authenticationManager.authenticate(any(Authentication.class))).thenThrow(BCE);

        // testing
        filter.doFilter(request, response, chain);
        // chain should stop here and it should send back a 500
        // future version should call some error handler
        verify(chain, never()).doFilter(any(ServletRequest.class), any(ServletResponse.class));

        return BCE;
    }

    private void createHandler() {
        successHandler = mock(AuthenticationSuccessHandler.class);
        failureHandler = mock(AuthenticationFailureHandler.class);
        filter.setAuthenticationSuccessHandler(successHandler);
        filter.setAuthenticationFailureHandler(failureHandler);
    }

    @AfterEach
    public void after() {
        securityContextHolderStrategy.clearContext();
    }

    private Authentication currentAuthentication() {
        return securityContextHolderStrategy.getContext().getAuthentication();
    }

    private void setCurrentAuthentication(Authentication authentication) {
        SecurityContext context = securityContextHolderStrategy.createEmptyContext();
        context.setAuthentication(authentication);
        securityContextHolderStrategy.setContext(context);
    }

    private static final class TestSecurityContextHolderStrategy implements SecurityContextHolderStrategy {
        private final ThreadLocal<SecurityContext> contextHolder = new ThreadLocal<>();

        @Override
        public void clearContext() {
            contextHolder.remove();
        }

        @Override
        public SecurityContext getContext() {
            SecurityContext context = contextHolder.get();
            if (context == null) {
                context = createEmptyContext();
                contextHolder.set(context);
            }
            return context;
        }

        @Override
        public Supplier<SecurityContext> getDeferredContext() {
            return this::getContext;
        }

        @Override
        public void setContext(SecurityContext context) {
            contextHolder.set(context);
        }

        @Override
        public SecurityContext createEmptyContext() {
            return new SecurityContextImpl();
        }
    }

}
