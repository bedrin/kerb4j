package com.kerb4j.common.marshall.pac;

public interface PacConstants {

    int PAC_VERSION = 0;

    int LOGON_INFO = 1;
    int SERVER_CHECKSUM = 6;
    int PRIVSVR_CHECKSUM = 7;

    int LOGON_EXTRA_SIDS = 0x20;
    int LOGON_RESOURCE_GROUPS = 0x200;

    long FILETIME_BASE = -11644473600000L;

}
