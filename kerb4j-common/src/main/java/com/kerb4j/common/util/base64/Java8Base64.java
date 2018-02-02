package com.kerb4j.common.util.base64;

import java.util.Base64;

public class Java8Base64 implements Base64CodecImpl {

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
