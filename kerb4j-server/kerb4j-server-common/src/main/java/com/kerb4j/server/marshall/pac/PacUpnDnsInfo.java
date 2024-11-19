package com.kerb4j.server.marshall.pac;

import com.kerb4j.server.marshall.Kerb4JException;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Structure representing the UPN_DNS_INFO record
 * <p>
 * <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/166d8064-c863-41e1-9c23-edaaa5f36962?redirectedfrom=MSDN">Section 2.10 UPN_DNS_INFO</a>
 *
 * @author vfalta@techniserv.cz
 */
public class PacUpnDnsInfo {
    public static final int FLAG_HAS_UPN_BIT = 0x1;
    public static final int FLAG_HAS_SAM_BIT = 0x2;

    private final String upn;
    private final String dnsDomainName;

    private final int flags;

    /**
     * Only present if the FLAG_HAS_SAM_BIT is set.
     * Check the hasSam() method.
     */
    private String sam;

    /**
     * Only present if the FLAG_HAS_UPN_BIT is set
     * Check the hasSam() method.
     */
    private PacSid sid;

    public PacUpnDnsInfo(byte[] bufferData) throws Kerb4JException {
        try {
            PacDataInputStream pacStream = new PacDataInputStream(new DataInputStream(
                    new ByteArrayInputStream(bufferData)));

            short upnLength = pacStream.readShort();
            short upnOffset = pacStream.readShort();

            short dnsDomainNameLength = pacStream.readShort();
            short dnsDomainNameOffset = pacStream.readShort();

            flags = pacStream.readInt();

            if (hasSam()) {
                readSam(bufferData, pacStream);
                readSid(bufferData, pacStream);
            }

            upn = readString(bufferData, upnLength, upnOffset);

            dnsDomainName = readString(bufferData, dnsDomainNameLength, dnsDomainNameOffset);
        } catch (IOException e) {
            throw new Kerb4JException("pac.upndnsinfo.malformed", null, e);
        }
    }

    /**
     * Get the userPrincipalName (UPN) attribute or UPN constructed from username and dnsDomainName fields
     *
     * @return the user's UPN
     */
    public String getUpn() {
        return upn;
    }

    /**
     * Get the DNS domain name of the user
     *
     * @return the user's DNS domain name
     */
    public String getDnsDomainName() {
        return dnsDomainName;
    }

    /**
     * Raw flags field from the UPN_DNS_INFO structure
     *
     * @return the flags field
     */
    public int getFlags() {
        return flags;
    }

    /**
     * @return whether the userPrincipalName attribute is set explicitly or
     * was constructed from username and domainName fields
     */
    public boolean hasUpn() {
        return (flags & FLAG_HAS_UPN_BIT) != 0;
    }

    /**
     * @return Whether the SAM and SID fields are present
     */
    public boolean hasSam() {
        return (flags & FLAG_HAS_SAM_BIT) != 0;
    }

    /**
     * Get the sAMAccountName attribute
     *
     * @return the user's SAM
     */
    public String getSam() {
        if (!hasSam()) {
            throw new IllegalStateException("No SAM present");
        }
        return sam;
    }

    /**
     * Get the SID of the user
     *
     * @return the user's SID
     */
    public PacSid getSid() {
        if (!hasSam()) {
            throw new IllegalStateException("No SAM present");
        }
        return sid;
    }

    private void readSam(byte[] bufferData, PacDataInputStream pacStream) throws IOException {
        short samLength = pacStream.readShort();
        short samOffset = pacStream.readShort();

        sam = readString(bufferData, samLength, samOffset);
    }

    private void readSid(byte[] bufferData, PacDataInputStream pacStream) throws IOException, Kerb4JException {
        short sidLength = pacStream.readShort();
        short sidOffset = pacStream.readShort();

        sid = new PacSid(readByteString(bufferData, sidLength, sidOffset));
    }

    private String readString(byte[] bufferData, short length, short offset) {
        byte[] data = new byte[length];
        System.arraycopy(bufferData, offset, data, 0, length);
        return new String(data, StandardCharsets.UTF_16LE);
    }

    private byte[] readByteString(byte[] bufferData, short length, short offset) {
        byte[] data = new byte[length];
        System.arraycopy(bufferData, offset, data, 0, length);
        return data;
    }
}
