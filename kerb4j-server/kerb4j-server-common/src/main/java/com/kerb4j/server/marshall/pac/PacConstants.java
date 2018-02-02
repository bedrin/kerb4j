package com.kerb4j.server.marshall.pac;

public interface PacConstants {

    int PAC_VERSION = 0;
    int LOGON_INFO = 1;
    int CREDENTIAL_TYPE = 2;
    int SERVER_CHECKSUM = 6;
    int PRIVSVR_CHECKSUM = 7;

    int CLIENT_INFO_TYPE = 10;
    int S4U_DELEGATION_INFO = 11;

    int LOGON_EXTRA_SIDS = 0x20;
    int LOGON_RESOURCE_GROUPS = 0x200;

    long FILETIME_BASE = -11644473600000L;

    int MD5_KRB_SALT = 17;
    int MD5_BLOCK_LENGTH = 64;

}
