package com.kerb4j.common.util;

import javax.xml.bind.DatatypeConverter;
import java.util.Base64;

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

    private interface Base64CodecImpl {

        String encodeImpl(byte[] data);

        byte[] decodeImpl(String data);

    }

    public static class DatatypeConverterCodec implements Base64CodecImpl {

        @Override
        public String encodeImpl(byte[] data) {
            return DatatypeConverter.printBase64Binary(data);
        }

        @Override
        public byte[] decodeImpl(String data) {
            return DatatypeConverter.parseBase64Binary(data);
        }
    }

    public static class Java8Base64 implements Base64CodecImpl {

        public static final Base64.Encoder ENCODER = Base64.getEncoder();
        public static final Base64.Decoder DECODER = Base64.getDecoder();

        @Override
        public String encodeImpl(byte[] data) {
            return ENCODER.encodeToString(data);
        }

        @Override
        public byte[] decodeImpl(String data) {
            return DECODER.decode(data);
        }
    }

}
