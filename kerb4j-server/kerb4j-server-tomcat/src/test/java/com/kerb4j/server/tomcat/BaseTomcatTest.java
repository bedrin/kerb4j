package com.kerb4j.server.tomcat;

import com.kerb4j.KerberosSecurityTestcase;
import com.kerb4j.MiniKdc;
import com.kerb4j.client.SpnegoClient;
import com.kerb4j.client.SpnegoHttpURLConnection;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.WebResourceRoot;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.webresources.DirResourceSet;
import org.apache.catalina.webresources.StandardRoot;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;

import static org.junit.Assert.assertEquals;

public class BaseTomcatTest extends KerberosSecurityTestcase {

    private Tomcat tomcat;

    private String host;

    private String clientPrincipal;
    private File clientKeytab;

    @Before
    public void startTomcat() throws Exception {

        MiniKdc kdc = getKdc();
        File workDir = getWorkDir();
        host = InetAddress.getLocalHost().getCanonicalHostName().toLowerCase(); // doesn't work without toLowerCse

        String serverPrincipal = "HTTP/" + host;
        File serverKeytab = new File(workDir, "server.keytab");
        kdc.createPrincipal(serverKeytab, serverPrincipal);

        clientPrincipal = "client/" + host;
        clientKeytab = new File(workDir, "client.keytab");
        kdc.createPrincipal(clientKeytab, clientPrincipal);

        tomcat = new Tomcat();
        tomcat.setPort(8080);

        StandardContext ctx = (StandardContext) tomcat.addWebapp("/", new File(".").getAbsolutePath());
        SpnegoAuthenticator valve = new SpnegoAuthenticator();
        valve.setKeyTab(serverKeytab.getAbsolutePath());
        valve.setPrincipalName(serverPrincipal);
        ctx.addValve(valve);

        //Tomcat.addServlet(ctx, "dummyServlet", new DummyServlet());

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

    @After
    public void stopTomcat() throws LifecycleException {

        tomcat.stop();
        tomcat.getServer().await();

    }


    @Test
    public void test1() throws Exception {

        {
            HttpURLConnection urlConnection = (HttpURLConnection) new URL("http://localhost:8080/dummy").openConnection();
            assertEquals(401, urlConnection.getResponseCode());
        }

        {
            SpnegoClient spnegoClient = SpnegoClient.loginWithKeyTab(clientPrincipal, clientKeytab.getAbsolutePath());
            HttpURLConnection huc = new SpnegoHttpURLConnection(spnegoClient).connect(new URL("http://" + host + ":" + 8080 + "/dummy"));

            assertEquals(200, huc.getResponseCode());
            assertEquals("Hello, world!", new BufferedReader(new InputStreamReader(huc.getInputStream())).readLine());
        }

    }

}
