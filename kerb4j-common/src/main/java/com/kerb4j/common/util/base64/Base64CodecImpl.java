package com.kerb4j.common.util.base64;

interface Base64CodecImpl {

    String encodeImpl(byte[] data);

    byte[] decodeImpl(String data);

}
