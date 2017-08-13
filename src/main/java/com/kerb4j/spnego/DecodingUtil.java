package com.kerb4j.spnego;

import com.kerb4j.Kerb4JException;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;

import java.io.IOException;
import java.util.Enumeration;

public final class DecodingUtil {

    private static final String FORMAT = "%1$02x";

    private DecodingUtil() {}

    public static final String asHexString(byte[] bytes) {
        StringBuilder builder = new StringBuilder();
        for(byte b : bytes)
            builder.append(String.format(FORMAT, b));

        return builder.toString();
    }

    public static final byte[] asBytes(int integer) {
        byte[] bytes = new byte[]{(byte)integer, (byte)(integer >>> 8), (byte)(integer >>> 16),
                (byte)(integer >>> 24)};

        return bytes;
    }

    public static <T> T as(Class<T> type, Object object) throws Kerb4JException {

        if(!type.isInstance(object)) {
            Object[] args = new Object[]{type, object.getClass()};
            throw new Kerb4JException("object.cast.fail", args, null);
        }

        return type.cast(object);
    }

    public static <T extends Object> T as(Class<T> type, Enumeration<?> enumeration)
            throws Kerb4JException {

        return as(type, enumeration.nextElement());
    }

    public static <T extends ASN1Encodable> T as(Class<T> type, ASN1InputStream stream)
            throws Kerb4JException, IOException {

        return as(type, stream.readObject());
    }

    public static <T extends ASN1Encodable> T as(Class<T> type, ASN1TaggedObject tagged)
            throws Kerb4JException {

        return as(type, tagged.getObject());
    }

    public static <T extends ASN1Encodable> T as(Class<T> type, DERSequence sequence, int index)
            throws Kerb4JException {

        return as(type, sequence.getObjectAt(index));
    }

}
