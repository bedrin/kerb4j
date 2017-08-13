package com.kerb4j.spnego;

import com.kerb4j.Kerb4JException;
import org.apache.kerby.asn1.parse.Asn1Container;
import org.apache.kerby.asn1.parse.Asn1ParseResult;
import org.apache.kerby.asn1.parse.Asn1Parser;
import org.apache.kerby.asn1.type.Asn1ObjectIdentifier;
import org.apache.kerby.kerberos.kerb.type.ap.ApReq;

import javax.security.auth.kerberos.KerberosKey;
import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * https://tools.ietf.org/html/rfc1964
 * <p>
 * Per RFC-1508, Appendix B, the initial context establishment token
 * will be enclosed within framing as follows:
 * <p>
 * InitialContextToken ::=
 * [APPLICATION 0] IMPLICIT SEQUENCE {
 * thisMech        MechType
 * -- MechType is OBJECT IDENTIFIER
 * -- representing "Kerberos V5"
 * innerContextToken ANY DEFINED BY thisMech
 * -- contents mechanism-specific;
 * -- ASN.1 usage within innerContextToken
 * -- is not required
 * }
 */
public class SpnegoKerberosMechToken {

    private ApReq apRequest;

    public SpnegoKerberosMechToken(byte[] token) throws Kerb4JException {
        this(token, null);
    }

    public SpnegoKerberosMechToken(byte[] token, KerberosKey[] keys) throws Kerb4JException {

        if (token.length <= 0)
            throw new Kerb4JException("kerberos.token.empty", null, null);

        try {

            Asn1ParseResult asn1ParseResult = Asn1Parser.parse(ByteBuffer.wrap(token));

            Asn1ParseResult item1 = ((Asn1Container) asn1ParseResult).getChildren().get(0);
            Asn1ObjectIdentifier asn1ObjectIdentifier = new Asn1ObjectIdentifier();
            asn1ObjectIdentifier.decode(item1);

            if (!asn1ObjectIdentifier.getValue().equals(SpnegoConstants.KERBEROS_MECHANISM))
                throw new Kerb4JException("kerberos.token.malformed", null, null);

            Asn1ParseResult item2 = ((Asn1Container) asn1ParseResult).getChildren().get(1);
            int read = 0;
            int readLow = item2.getBodyBuffer().get(item2.getOffset()) & 0xff;
            int readHigh = item2.getBodyBuffer().get(item2.getOffset() + 1) & 0xff;
            read = (readHigh << 8) + readLow;
            if (read != 0x01)
                throw new Kerb4JException("kerberos.token.malformed", null, null);

            Asn1ParseResult item3 = ((Asn1Container) asn1ParseResult).getChildren().get(2);

            ApReq apReq = new ApReq();
            apReq.decode(item3);
            apRequest = apReq;

            //apRequest = KrbCodec.decode(krbToken.getEncoded(), ApReq.class);

        } catch (IOException e) {
            throw new Kerb4JException("kerberos.token.malformed", null, e);
        }
    }

    public ApReq getApRequest() {
        return apRequest;
    }

}
