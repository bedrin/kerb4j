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
package com.kerb4j.server.spring;

import com.kerb4j.KerberosSecurityTestcase;
import com.kerb4j.server.spring.jaas.sun.SunJaasKerberosTicketValidator;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.apache.kerby.kerberos.kerb.server.SimpleKdcServer;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.core.io.FileSystemResource;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.io.File;
import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Test class for {@link KerberosAuthenticationProvider}
 *
 * @author Mike Wiesner
 * @since 1.0
 */
public class SpnegoAuthenticationProviderTest extends KerberosSecurityTestcase {

    @TempDir
    Path tempDir;

    public static final String SERVER_SPN = "HTTP/server.springsource.org";
    private SpnegoAuthenticationProvider provider;
    private UserDetailsService userDetailsService;

    private static final String TEST_USER = "Testuser";
    private static final String TEST_PASSWORD = "password";
    private static final UsernamePasswordAuthenticationToken INPUT_TOKEN = new UsernamePasswordAuthenticationToken(TEST_USER, TEST_PASSWORD);
    private static final List<GrantedAuthority> AUTHORITY_LIST = AuthorityUtils.createAuthorityList("ROLE_ADMIN");
    private static final UserDetails USER_DETAILS = new User(TEST_USER, TEST_PASSWORD, true, true, true, true, AUTHORITY_LIST);

    @BeforeEach
    public void before() throws Exception {
        // mocking
        SimpleKdcServer kdc = getKdc();
        kdc.createPrincipal(TEST_USER, TEST_PASSWORD);
        Assertions.assertTrue(Files.isDirectory(tempDir));
        Path keytabFilePath = Paths.get(tempDir.toFile().getAbsolutePath(),"serverKeyTab.keytab");
        Files.deleteIfExists(keytabFilePath);
        File keytabFile = keytabFilePath.toFile();
        kdc.createAndExportPrincipals(keytabFile, SERVER_SPN);

        this.userDetailsService = mock(UserDetailsService.class);

        this.provider = new SpnegoAuthenticationProvider();
        this.provider.setServerSpn(SERVER_SPN);

        SunJaasKerberosTicketValidator ticketValidator = new SunJaasKerberosTicketValidator();
        ticketValidator.setServicePrincipal(SERVER_SPN);
        ticketValidator.setKeyTabLocation(new FileSystemResource(keytabFile));
        ticketValidator.afterPropertiesSet();
        this.provider.setTicketValidator(ticketValidator);
        this.provider.setUserDetailsService(userDetailsService);
        this.provider.setExtractGroupsUserDetailsService(new ExtractGroupsUserDetailsService());
    }

    @Test
    public void testLoginWithUserNameAndPasswordOk() {

        when(userDetailsService.loadUserByUsername(TEST_USER)).thenReturn(USER_DETAILS);

        Authentication authenticate = provider.authenticate(INPUT_TOKEN);

        Assertions.assertNotNull(authenticate);
        Assertions.assertEquals(TEST_USER, authenticate.getName());

    }
}
