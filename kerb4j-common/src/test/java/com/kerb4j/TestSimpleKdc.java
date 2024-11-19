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
package com.kerb4j;

import org.apache.kerby.kerberos.kerb.keytab.Keytab;
import org.apache.kerby.kerberos.kerb.server.SimpleKdcServer;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import java.io.File;
import java.security.Principal;
import java.util.*;

public class TestSimpleKdc extends KerberosSecurityTestcase {

    @Test
    public void testSimpleKdcStart() {
        SimpleKdcServer kdc = getKdc();
        Assertions.assertNotSame(0, kdc.getKdcPort());
    }

    @Test
    public void testKeytabGen() throws Exception {
        SimpleKdcServer kdc = getKdc();
        File workDir = getWorkDir();

        kdc.createAndExportPrincipals(new File(workDir, "keytab"), "foo/bar", "bar/foo");
        Keytab kt = Keytab.loadKeytab(new File(workDir, "keytab"));
        Set<String> principals = new HashSet<String>();
        for (PrincipalName principalName : kt.getPrincipals()) {
            if (!principalName.getName().startsWith("krbtgt") && !principalName.getName().startsWith("kadmin")) {
                principals.add(principalName.getName());
            }
        }
        // here principals used to use \ instead of /
        // because
        // org.apache.directory.server.kerberos.shared.keytab.KeytabDecoder
        // .getPrincipalName(IoBuffer buffer) use \\ when generates principal
        // with updadte of apache ds it is / again
        Assertions.assertEquals(
                new HashSet<>(Arrays.asList("foo/bar@" + kdc.getKdcConfig().getKdcRealm(), "bar/foo@" + kdc.getKdcConfig().getKdcRealm())),
                principals);
    }

    @Test
    public void testKerberosLogin() throws Exception {
        SimpleKdcServer kdc = getKdc();
        File workDir = getWorkDir();
        LoginContext loginContext = null;
        try {
            String principal = "foo";
            File keytab = new File(workDir, "foo.keytab");
            kdc.createAndExportPrincipals(keytab, principal);

            Set<Principal> principals = new HashSet<Principal>();
            principals.add(new KerberosPrincipal(principal));

            // client login
            Subject subject = new Subject(false, principals, new HashSet<Object>(), new HashSet<Object>());
            loginContext = new LoginContext("", subject, null, KerberosConfiguration.createClientConfig(principal,
                    keytab));
            loginContext.login();
            subject = loginContext.getSubject();
            Assertions.assertEquals(1, subject.getPrincipals().size());
            Assertions.assertEquals(KerberosPrincipal.class, subject.getPrincipals().iterator().next().getClass());
            Assertions.assertEquals(principal + "@" + kdc.getKdcConfig().getKdcRealm(), subject.getPrincipals().iterator().next().getName());
            loginContext.logout();
            loginContext = null;

            // server login
            subject = new Subject(false, principals, new HashSet<Object>(), new HashSet<Object>());
            loginContext = new LoginContext("", subject, null, KerberosConfiguration.createServerConfig(principal,
                    keytab));
            loginContext.login();
            subject = loginContext.getSubject();
            Assertions.assertEquals(1, subject.getPrincipals().size());
            Assertions.assertEquals(KerberosPrincipal.class, subject.getPrincipals().iterator().next().getClass());
            Assertions.assertEquals(principal + "@" + kdc.getKdcConfig().getKdcRealm(), subject.getPrincipals().iterator().next().getName());
            loginContext.logout();
            loginContext = null;

        } finally {
            if (loginContext != null) {
                loginContext.logout();
            }
        }
    }

    private static class KerberosConfiguration extends Configuration {
        private String principal;
        private String keytab;
        private boolean isInitiator;

        private KerberosConfiguration(String principal, File keytab, boolean client) {
            this.principal = principal;
            this.keytab = keytab.getAbsolutePath();
            this.isInitiator = client;
        }

        public static Configuration createClientConfig(String principal, File keytab) {
            return new KerberosConfiguration(principal, keytab, true);
        }

        public static Configuration createServerConfig(String principal, File keytab) {
            return new KerberosConfiguration(principal, keytab, false);
        }

        private static String getKrb5LoginModuleName() {
            return System.getProperty("java.vendor").contains("IBM") ? "com.ibm.security.auth.module.Krb5LoginModule"
                    : "com.sun.security.auth.module.Krb5LoginModule";
        }

        @Override
        public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
            Map<String, String> options = new HashMap<String, String>();
            options.put("keyTab", keytab);
            options.put("principal", principal);
            options.put("useKeyTab", "true");
            options.put("storeKey", "true");
            options.put("doNotPrompt", "true");
            options.put("useTicketCache", "true");
            options.put("renewTGT", "true");
            options.put("refreshKrb5Config", "true");
            options.put("isInitiator", Boolean.toString(isInitiator));
            String ticketCache = System.getenv("KRB5CCNAME");
            if (ticketCache != null) {
                options.put("ticketCache", ticketCache);
            }
            options.put("debug", "true");

            return new AppConfigurationEntry[]{new AppConfigurationEntry(getKrb5LoginModuleName(),
                    AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options)};
        }
    }

}
