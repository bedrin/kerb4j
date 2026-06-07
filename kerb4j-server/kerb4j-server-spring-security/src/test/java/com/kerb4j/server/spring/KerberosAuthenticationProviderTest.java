package com.kerb4j.server.spring;

import com.kerb4j.KerberosSecurityTestcase;
import org.apache.kerby.kerberos.kerb.server.SimpleKdcServer;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.util.List;

import static org.mockito.Mockito.when;

/**
 * Test class for {@link com.kerb4j.server.spring.KerberosAuthenticationProvider}
 *
 * @author Mike Wiesner
 */
public class KerberosAuthenticationProviderTest extends KerberosSecurityTestcase {

    private static final String TEST_USER = "Testuser";
    private static final String TEST_PASSWORD = "password";
    private static final UsernamePasswordAuthenticationToken INPUT_TOKEN = new UsernamePasswordAuthenticationToken(TEST_USER, TEST_PASSWORD);
    private static final List<GrantedAuthority> AUTHORITY_LIST = AuthorityUtils.createAuthorityList("ROLE_ADMIN");
    private static final UserDetails USER_DETAILS = new User(TEST_USER, TEST_PASSWORD, true, true, true, true, AUTHORITY_LIST);
    private com.kerb4j.server.spring.KerberosAuthenticationProvider provider;
    @Mock
    private UserDetailsService userDetailsService;

    @BeforeEach
    public void before() {
        MockitoAnnotations.openMocks(this);
        this.provider = new KerberosAuthenticationProvider();
        this.provider.setUserDetailsService(userDetailsService);
    }

    @Test
    public void testLoginOk() throws Exception {
        SimpleKdcServer kdc = getKdc();
        kdc.createPrincipal(TEST_USER, TEST_PASSWORD);

        when(userDetailsService.loadUserByUsername(TEST_USER)).thenReturn(USER_DETAILS);

        Authentication authenticate = provider.authenticate(INPUT_TOKEN);

        Assertions.assertNotNull(authenticate);
        Assertions.assertEquals(TEST_USER, authenticate.getName());
        Assertions.assertEquals(USER_DETAILS, authenticate.getPrincipal());
        Assertions.assertEquals(TEST_PASSWORD, authenticate.getCredentials());
        Assertions.assertEquals(AUTHORITY_LIST, authenticate.getAuthorities());

    }

    @Test
    public void testLoginFailed() {
        SimpleKdcServer kdc = getKdc();
        Exception exception = Assertions.assertThrows(Exception.class, () -> {
            kdc.createPrincipal(TEST_USER, TEST_PASSWORD + "nonce");
            when(userDetailsService.loadUserByUsername(TEST_USER)).thenReturn(USER_DETAILS);
            provider.authenticate(INPUT_TOKEN);
        });
        Assertions.assertNotNull(exception);
    }
}
