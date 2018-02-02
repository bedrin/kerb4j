package com.kerb4j.common.util.base64;

import javax.xml.bind.DatatypeConverter;

public class DatatypeConverterCodec implements Base64CodecImpl {

    @Override
    public String encodeImpl(byte[] data) {
        return DatatypeConverter.printBase64Binary(data);
    }

    @Override
    public byte[] decodeImpl(String data) {
        return DatatypeConverter.parseBase64Binary(data);
    }
}
