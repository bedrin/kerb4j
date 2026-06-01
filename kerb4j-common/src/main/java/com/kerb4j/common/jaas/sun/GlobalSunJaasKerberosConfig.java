package com.kerb4j.common.jaas.sun;

/**
 * Config for global jaas.
 *
 * @author Mike Wiesner
 */
public class GlobalSunJaasKerberosConfig {

    /**
     * Enable debug logs from the Sun Kerberos Implementation. Default is false.
     *
     * @param debug true if debug should be enabled
     */
    public void setDebug(boolean debug) {
        if (debug) {
            System.setProperty("sun.security.krb5.debug", "true");
        }
    }

    /**
     * Kerberos config file location can be specified here.
     *
     * @param krbConfLocation the path to krb config file
     */
    public void setKrbConfLocation(String krbConfLocation) {
        if (krbConfLocation != null) {
            System.setProperty("java.security.krb5.conf", krbConfLocation);
        }
    }

}
