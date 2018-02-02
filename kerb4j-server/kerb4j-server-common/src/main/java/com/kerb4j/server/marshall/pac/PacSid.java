package com.kerb4j.server.marshall.pac;

import com.kerb4j.server.marshall.Kerb4JException;

public class PacSid {

    private static final String FORMAT = "%1$02x";

    private byte revision;
    private byte subCount;
    private byte[] authority;
    private byte[] subs;

    public PacSid(byte[] bytes) throws Kerb4JException {
        if (bytes.length < 8 || ((bytes.length - 8) % 4) != 0
                || ((bytes.length - 8) / 4) != bytes[1])
            throw new Kerb4JException("pac.sid.malformed.size", null, null);

        this.revision = bytes[0];
        this.subCount = bytes[1];
        this.authority = new byte[6];
        System.arraycopy(bytes, 2, this.authority, 0, 6);
        this.subs = new byte[bytes.length - 8];
        System.arraycopy(bytes, 8, this.subs, 0, bytes.length - 8);
    }

    public PacSid(PacSid sid) {
        this.revision = sid.revision;
        this.subCount = sid.subCount;
        this.authority = new byte[6];
        System.arraycopy(sid.authority, 0, this.authority, 0, 6);
        this.subs = new byte[sid.subs.length];
        System.arraycopy(sid.subs, 0, this.subs, 0, sid.subs.length);
    }

    public static String convertSidToStringSid(byte[] sid) {
        int offset, size;

        // sid[0] is the Revision, we allow only version 1, because it's the
        // only that exists right now.
        if (sid[0] != 1)
            throw new IllegalArgumentException("SID revision must be 1");

        StringBuilder stringSidBuilder = new StringBuilder("S-1-");

        // The next byte specifies the numbers of sub authorities (number of
        // dashes minus two)
        int subAuthorityCount = sid[1] & 0xFF;

        // IdentifierAuthority (6 bytes starting from the second) (big endian)
        long identifierAuthority = 0;
        offset = 2;
        size = 6;
        for (int i = 0; i < size; i++) {
            identifierAuthority |= (long) (sid[offset + i] & 0xFF) << (8 * (size - 1 - i));
            // The & 0xFF is necessary because byte is signed in Java
        }
        if (identifierAuthority < Math.pow(2, 32)) {
            stringSidBuilder.append(Long.toString(identifierAuthority));
        } else {
            stringSidBuilder.append("0x").append(
                    Long.toHexString(identifierAuthority).toUpperCase());
        }

        // Iterate all the SubAuthority (little-endian)
        offset = 8;
        size = 4; // 32-bits (4 bytes) for each SubAuthority
        for (int i = 0; i < subAuthorityCount; i++, offset += size) {
            long subAuthority = 0;
            for (int j = 0; j < size; j++) {
                subAuthority |= (long) (sid[offset + j] & 0xFF) << (8 * j);
                // The & 0xFF is necessary because byte is signed in Java
            }
            stringSidBuilder.append("-").append(subAuthority);
        }

        return stringSidBuilder.toString();
    }

    public static String toString(byte[] bytes) {
        StringBuilder builder = new StringBuilder();

        for (int i = 0; i < bytes.length; i++) {
            int unsignedByte = ((int) bytes[i]) & 0xff;
            builder.append("\\").append(String.format(FORMAT, unsignedByte));
        }

        return builder.toString();
    }

    public static PacSid createFromSubs(byte[] bytes) throws Kerb4JException {
        if ((bytes.length % 4) != 0) {
            Object[] args = new Object[]{bytes.length};
            throw new Kerb4JException("pac.subauthority.malformed.size", args, null);
        }

        byte[] sidBytes = new byte[8 + bytes.length];
        sidBytes[0] = 1;
        sidBytes[1] = (byte) (bytes.length / 4);
        System.arraycopy(new byte[]{0, 0, 0, 0, 0, 5}, 0, sidBytes, 2, 6);
        System.arraycopy(bytes, 0, sidBytes, 8, bytes.length);

        return new PacSid(sidBytes);
    }

    public static PacSid append(PacSid sid1, PacSid sid2) {
        PacSid sid = new PacSid(sid1);

        sid.subCount += sid2.subCount;
        sid.subs = new byte[sid.subCount * 4];
        System.arraycopy(sid1.subs, 0, sid.subs, 0, sid1.subs.length);
        System.arraycopy(sid2.subs, 0, sid.subs, sid1.subs.length, sid2.subs.length);

        return sid;
    }

    // https://msdn.microsoft.com/en-us/library/ff632068.aspx
    public String toHumanReadableString() {
        return convertSidToStringSid(getBytes());
    }

    public String toString() {
        StringBuilder builder = new StringBuilder();

        builder.append("\\").append(String.format(FORMAT, ((int) revision) & 0xff));
        builder.append("\\").append(String.format(FORMAT, ((int) subCount) & 0xff));
        for (int i = 0; i < authority.length; i++) {
            int unsignedByte = ((int) authority[i]) & 0xff;
            builder.append("\\").append(String.format(FORMAT, unsignedByte));
        }
        for (int i = 0; i < subs.length; i++) {
            int unsignedByte = ((int) subs[i]) & 0xff;
            builder.append("\\").append(String.format(FORMAT, unsignedByte));
        }

        return builder.toString();
    }

    public boolean isEmpty() {
        return subCount == 0;
    }

    public boolean isBlank() {
        boolean blank = true;
        for (byte sub : subs)
            blank = blank && (sub == 0);
        return blank;
    }

    public byte[] getBytes() {
        byte[] bytes = new byte[8 + subCount * 4];
        bytes[0] = revision;
        bytes[1] = subCount;
        System.arraycopy(authority, 0, bytes, 2, 6);
        System.arraycopy(subs, 0, bytes, 8, subs.length);

        return bytes;
    }

}
