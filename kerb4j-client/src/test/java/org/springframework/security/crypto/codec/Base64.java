package org.springframework.security.crypto.codec;

final public class Base64 {
    private Base64() {
    }

    public static byte[] decode(byte[] src) {
        return java.util.Base64.getDecoder().decode(src);
    }

    public static byte[] encode(byte[] src) {
        return java.util.Base64.getEncoder().encode(src);
    }
}
