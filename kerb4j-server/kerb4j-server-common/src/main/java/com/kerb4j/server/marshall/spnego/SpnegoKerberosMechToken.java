package com.kerb4j.server.marshall.spnego;

import com.kerb4j.server.marshall.Kerb4JException;
import com.kerb4j.server.marshall.pac.Pac;
import com.kerb4j.common.util.SpnegoProvider;
import org.apache.kerby.asn1.parse.Asn1Container;
import org.apache.kerby.asn1.parse.Asn1ParseResult;
import org.apache.kerby.asn1.parse.Asn1Parser;
import org.apache.kerby.asn1.type.Asn1ObjectIdentifier;
import org.apache.kerby.kerberos.kerb.KrbCodec;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.crypto.EncryptionHandler;
import org.apache.kerby.kerberos.kerb.type.ad.AuthorizationData;
import org.apache.kerby.kerberos.kerb.type.ad.AuthorizationDataEntry;
import org.apache.kerby.kerberos.kerb.type.ap.ApReq;
import org.apache.kerby.kerberos.kerb.type.base.EncryptedData;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;
import org.apache.kerby.kerberos.kerb.type.base.KeyUsage;
import org.apache.kerby.kerberos.kerb.type.ticket.EncTicketPart;

import javax.security.auth.kerberos.KerberosKey;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;

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

        if (token.length <= 0)
            throw new Kerb4JException("kerberos.token.empty", null, null);

        try {

            Asn1ParseResult asn1ParseResult = Asn1Parser.parse(ByteBuffer.wrap(token));

            Asn1ParseResult item1 = ((Asn1Container) asn1ParseResult).getChildren().get(0);
            Asn1ObjectIdentifier asn1ObjectIdentifier = new Asn1ObjectIdentifier();
            asn1ObjectIdentifier.decode(item1);

            if (!asn1ObjectIdentifier.getValue().equals(SpnegoProvider.KERBEROS_MECHANISM))
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

            //apRequest = KrbCodec.decodeImpl(krbToken.getEncoded(), ApReq.class);

        } catch (IOException e) {
            throw new Kerb4JException("kerberos.token.malformed", null, e);
        }
    }

    public ApReq getApRequest() {
        return apRequest;
    }

    public KerberosKey getKerberosKey(EncryptionType eType, KerberosKey[] kerberosKeys) throws KrbException {

        for (KerberosKey kerberosKey : kerberosKeys) {
            if (kerberosKey.getKeyType() == eType.getValue()) {
                return kerberosKey;
            }
        }

        return null;

    }

    public EncTicketPart getEncryptedTicketPart(byte[] cipher, KerberosKey kerberosKey) throws KrbException {

        byte[] decrypt = EncryptionHandler.getEncHandler(kerberosKey.getKeyType()).decrypt(
                cipher,
                kerberosKey.getEncoded(),
                KeyUsage.KDC_REP_TICKET.getValue()
        );

        return KrbCodec.decode(decrypt, EncTicketPart.class);

    }

    public Pac getPac(KerberosKey[] kerberosKeys) throws KrbException, Kerb4JException {

        EncryptedData encryptedData = getApRequest().getTicket().getEncryptedEncPart();
        KerberosKey kerberosKey = getKerberosKey(encryptedData.getEType(), kerberosKeys);
        EncTicketPart tgsRep = getEncryptedTicketPart(encryptedData.getCipher(), kerberosKey);

        AuthorizationData authorizationData = tgsRep.getAuthorizationData();
        if (null == authorizationData) return null;

        List<AuthorizationDataEntry> authorizationDataEntries = authorizationData.getElements();

        return extractPac(authorizationDataEntries, kerberosKey);

    }

    private Pac extractPac(List<AuthorizationDataEntry> authorizationDataEntries, KerberosKey kerberosKey) throws Kerb4JException {

        for (AuthorizationDataEntry authorizationDataEntry : authorizationDataEntries) {
            switch (authorizationDataEntry.getAuthzType()) {
                case AD_IF_RELEVANT:
                    Pac pac = extractPac(authorizationDataEntry.getAuthzDataAs(AuthorizationData.class).getElements(), kerberosKey);
                    if (null != pac) {
                        return pac;
                    } else {
                        continue;
                    }
                case AD_WIN2K_PAC:
                    return new Pac(authorizationDataEntry.getAuthzData(), kerberosKey);
            }
        }

        return null;

    }

}
