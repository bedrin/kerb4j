package org.jaaslounge.decoding.kerberos;

public interface KerberosConstants {

    String KERBEROS_OID = "1.2.840.113554.1.2.2";
    String KERBEROS_VERSION = "5";

    String KERBEROS_AP_REQ = "14";
    
    int AF_INTERNET = 2;
    int AF_CHANET = 5;
    int AF_XNS = 6;
    int AF_ISO = 7;
    
    int AUTH_DATA_RELEVANT = 1;
    int AUTH_DATA_PAC = 128;

    int DES_ENC_TYPE = 3;
    int RC4_ENC_TYPE = 23;
    String RC4_ALGORITHM = "ARCFOUR";
    String HMAC_ALGORITHM = "HmacMD5";
    int CONFOUNDER_SIZE = 8;
    int CHECKSUM_SIZE = 16;

}