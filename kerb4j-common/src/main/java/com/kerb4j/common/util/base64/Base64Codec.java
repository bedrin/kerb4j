package com.kerb4j.common.util.base64;

public class Base64Codec {

    private final static Base64CodecImpl impl = getImpl();

    public static String encode(byte[] data) {
        return impl.encodeImpl(data);
    }

    public static byte[] decode(String data) {
        return impl.decodeImpl(data);
    }

    private static Base64CodecImpl getImpl() {
        try {
            Class.forName("java.util.Base64");
            return new Java8Base64();
        } catch (ClassNotFoundException e) {
            return new DatatypeConverterCodec();
        }
    }

}
