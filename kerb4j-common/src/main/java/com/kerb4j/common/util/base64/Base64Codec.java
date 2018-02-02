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
            try {
                Class.forName("java.util.Base64");
                return (Base64CodecImpl) Class.forName("com.kerb4j.common.util.base64.Java8Base64").
                        getConstructor().newInstance();
            } catch (ClassNotFoundException e) {
                return (Base64CodecImpl) Class.forName("com.kerb4j.common.util.base64.DatatypeConverterCodec").
                        getConstructor().newInstance();
            }
        } catch (Exception e) {
            return null;
        }
    }

}
