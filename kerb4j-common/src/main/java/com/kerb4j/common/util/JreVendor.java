package com.kerb4j.common.util;

import java.util.Locale;

public class JreVendor {

    public static final boolean IS_ORACLE_JVM;
    public static final boolean IS_IBM_JVM;

    static {
        /**
         * There are a few places where Tomcat either accesses JVM internals
         * (e.g. the memory leak protection) or where feature support varies
         * between JVMs (e.g. SPNEGO). These flags exist to enable Tomcat to
         * adjust its behaviour based on the vendor of the JVM. In an ideal
         * world this code would not exist.
         */
        String vendor = System.getProperty("java.vendor", "");
        vendor = vendor.toLowerCase(Locale.ENGLISH);

        if (vendor.startsWith("oracle") || vendor.startsWith("sun")) {
            IS_ORACLE_JVM = true;
            IS_IBM_JVM = false;
        } else if (vendor.contains("ibm")) {
            IS_ORACLE_JVM = false;
            IS_IBM_JVM = true;
        } else {
            IS_ORACLE_JVM = false;
            IS_IBM_JVM = false;
        }
    }

}
