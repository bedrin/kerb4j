package com.kerb4j.server.tomcat;

import com.kerb4j.KerberosSecurityTestcase;
import com.kerb4j.client.SpnegoClient;
import com.kerb4j.client.SpnegoHttpURLConnection;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.WebResourceRoot;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.webresources.DirResourceSet;
import org.apache.catalina.webresources.StandardRoot;
import org.apache.kerby.kerberos.kerb.server.SimpleKdcServer;
import org.ietf.jgss.GSSException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.security.PrivilegedActionException;

public class BaseTomcatTest extends KerberosSecurityTestcase {

    public static final int TOMCAT_PORT = 8080;
    private static final Logger LOG = LoggerFactory.getLogger(BaseTomcatTest.class);
    private Tomcat tomcat;

    private String host;

    private String clientPrincipal;
    private File clientKeytab;

    @BeforeEach
    public void startTomcat() throws Exception {
        SimpleKdcServer kdc = getKdc();
        File workDir = getWorkDir();
        host = InetAddress.getLocalHost().getCanonicalHostName().toLowerCase(); // doesn't work without toLowerCse

        String serverPrincipal = "HTTP/" + host;
        File serverKeytab = new File(workDir, "server.keytab");
        kdc.createAndExportPrincipals(serverKeytab, serverPrincipal);

        clientPrincipal = "client/" + host;
        clientKeytab = new File(workDir, "client.keytab");
        kdc.createAndExportPrincipals(clientKeytab, clientPrincipal);

        tomcat = new Tomcat();
        tomcat.getConnector();
        tomcat.setPort(TOMCAT_PORT);

        StandardContext ctx = (StandardContext) tomcat.addWebapp("", new File(".").getAbsolutePath());
        SpnegoAuthenticator valve = new SpnegoAuthenticator();
        valve.setKeyTab(serverKeytab.getAbsolutePath());
        valve.setPrincipalName(serverPrincipal);
        ctx.addValve(valve);

        Tomcat.addServlet(ctx, "dummyServlet", new DummyServlet());

        // Declare an alternative location for your "WEB-INF/classes" dir
        // Servlet 3.0 annotation will work
        File additionWebInfClasses = new File("target/test-classes");
        WebResourceRoot resources = new StandardRoot(ctx);
        resources.addPreResources(new DirResourceSet(resources, "/WEB-INF/classes",
                additionWebInfClasses.getAbsolutePath(), "/"));
        ctx.setResources(resources);

        ctx.setRealm(new SpnegoRealm());

        tomcat.start();
    }

    @AfterEach
    public void stopTomcat() throws LifecycleException {
        LOG.info("Stopping Tomcat server on port {}", TOMCAT_PORT);
        tomcat.stop();
        tomcat.destroy();
        LOG.info("Stopped Tomcat server on port {}", TOMCAT_PORT);
    }

    @Test
    public void testNoAuthResponse() throws IOException {
        HttpURLConnection urlConnection = (HttpURLConnection) new URL("http://localhost:" + TOMCAT_PORT + "/dummy").openConnection();
        Assertions.assertEquals(401, urlConnection.getResponseCode());
    }

    @Test
    public void test1() throws IOException, GSSException, PrivilegedActionException {
        SpnegoClient spnegoClient = SpnegoClient.loginWithKeyTab(clientPrincipal, clientKeytab.getAbsolutePath());
        HttpURLConnection huc = new SpnegoHttpURLConnection(spnegoClient).connect(new URL("http://" + host + ":" + TOMCAT_PORT + "/dummy"));
        Assertions.assertEquals(200, huc.getResponseCode());
        Assertions.assertEquals("Hello, world!",
                new BufferedReader(new InputStreamReader(huc.getInputStream())).readLine()
        );
    }
}