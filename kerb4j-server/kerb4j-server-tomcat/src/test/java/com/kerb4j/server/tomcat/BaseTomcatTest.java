package com.kerb4j.server.tomcat;

import org.apache.catalina.WebResourceRoot;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.webresources.DirResourceSet;
import org.apache.catalina.webresources.StandardRoot;
import org.jaaslounge.sso.tomcat.spnego.SpnegoValve;
import org.junit.Test;

import java.io.File;
import java.net.HttpURLConnection;
import java.net.URL;

public class BaseTomcatTest {

    @Test
    public void test1() throws Exception {
        startTomcat();
    }

    public void startTomcat() throws Exception {
        String webappDirLocation = "src/test/webapp/";
        Tomcat tomcat = new Tomcat();

        //The port that we should run on can be set into an environment variable
        //Look for that variable and default to 8080 if it isn't there.
        String webPort = System.getenv("PORT");
        if(webPort == null || webPort.isEmpty()) {
            webPort = "8080";
        }

        tomcat.setPort(Integer.valueOf(webPort));

        StandardContext ctx = (StandardContext) tomcat.addWebapp("/", new File(webappDirLocation).getAbsolutePath());
        ctx.addValve(new SpnegoValve());
        System.out.println("configuring app with basedir: " + new File("./" + webappDirLocation).getAbsolutePath());

        // Declare an alternative location for your "WEB-INF/classes" dir
        // Servlet 3.0 annotation will work
        File additionWebInfClasses = new File("target/classes");
        WebResourceRoot resources = new StandardRoot(ctx);
        resources.addPreResources(new DirResourceSet(resources, "/WEB-INF/classes",
                additionWebInfClasses.getAbsolutePath(), "/"));
        ctx.setResources(resources);

        tomcat.start();

        HttpURLConnection urlConnection = (HttpURLConnection) new URL("http://localhost:8080/index.html").openConnection();
        urlConnection.getResponseCode();

        tomcat.stop();
        tomcat.getServer().await();
    }

}
