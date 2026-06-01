package com.kerb4j.server.marshall.spnego;

import com.kerb4j.common.util.SpnegoProvider;
import com.kerb4j.server.marshall.Kerb4JException;
import com.kerb4j.server.marshall.pac.Pac;
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
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.ticket.EncTicketPart;
import org.apache.kerby.kerberos.kerb.type.ticket.Ticket;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import javax.security.auth.kerberos.KerberosKey;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
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
 * <a href="https://tools.ietf.org/html/rfc1964">rfc1964</a>
 */
@NullMarked
public class SpnegoKerberosMechToken {

    private final ApReq apRequest;

    public SpnegoKerberosMechToken(byte[] token) throws Kerb4JException {

        if (token.length == 0)
            throw new Kerb4JException("kerberos.token.empty", null, null);

        try {

            Asn1ParseResult asn1ParseResult = Asn1Parser.parse(ByteBuffer.wrap(token));

            // TODO: add null and boundaries checks below !

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

    public @Nullable KerberosKey getKerberosKey(EncryptionType eType, KerberosKey[] kerberosKeys) {

        for (KerberosKey kerberosKey : kerberosKeys) {
            if (kerberosKey.getKeyType() == eType.getValue()) {
                return kerberosKey;
            }
        }

        // TODO: add logging here - it might be useful; and a test for it

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

    /**
     * Get the canonical server principal name (SPN) from the unencrypted ticket metadata.
     * The name is built from the ticket's sname components and the ticket-level realm,
     * in the format {@code service/host@REALM} (e.g. {@code HTTP/www.example.com@EXAMPLE.COM}).
     * This is the same format users must use when configuring principals in
     * {@link com.kerb4j.server.MultiPrincipalManager}.
     *
     * @return the canonical server principal name including realm
     */
    public @Nullable String getServerPrincipalName() {
        @SuppressWarnings("NullableProblems") @Nullable Ticket ticket = getApRequest().getTicket();
        if (null == ticket) {
            return null;
        } else {
            @SuppressWarnings("NullableProblems") @Nullable PrincipalName sName = ticket.getSname();
            if (null == sName) {
                return null;
            } else {
                String name = buildPrincipalName(sName);
                if (name.isEmpty()) {
                    return null;
                }
                String realm = ticket.getRealm();
                if (realm != null && !realm.isEmpty() && !name.contains("@")) {
                    return name + "@" + realm;
                }
                return name;
            }
        }
    }

    private static String buildPrincipalName(PrincipalName principalName) {
        List<String> nameStrings = principalName.getNameStrings();
        if (nameStrings == null || nameStrings.isEmpty()) {
            String fallback = principalName.getName();
            return fallback == null ? "" : fallback;
        }

        List<String> sanitizedComponents = new ArrayList<>(nameStrings.size());
        for (String nameString : nameStrings) {
            if (nameString != null && !nameString.isEmpty()) {
                sanitizedComponents.add(nameString);
            }
        }
        if (sanitizedComponents.isEmpty()) {
            String fallback = principalName.getName();
            return fallback == null ? "" : fallback;
        }
        return String.join("/", sanitizedComponents);
    }

    public @Nullable Pac getPac(KerberosKey[] kerberosKeys) throws KrbException, Kerb4JException {

        @SuppressWarnings("NullableProblems") @Nullable Ticket ticket = getApRequest().getTicket();

        if (null == ticket) {
            return null;
        } else {
            @SuppressWarnings("NullableProblems") @Nullable EncryptedData encryptedData = ticket.getEncryptedEncPart();

            if (null == encryptedData) {
                return null;
            } else {
                KerberosKey kerberosKey = getKerberosKey(encryptedData.getEType(), kerberosKeys);

                if (null == kerberosKey) {
                    return null; // TODO: maybe add logging here there and everywhere
                } else {
                    EncTicketPart tgsRep = getEncryptedTicketPart(encryptedData.getCipher(), kerberosKey);

                    @SuppressWarnings("NullableProblems") @Nullable AuthorizationData authorizationData = tgsRep.getAuthorizationData();
                    if (null == authorizationData) {
                        return null;
                    } else {
                        List<AuthorizationDataEntry> authorizationDataEntries = authorizationData.getElements();
                        return extractPac(authorizationDataEntries, kerberosKey);
                    }
                }

            }

        }

    }

    private @Nullable Pac extractPac(List<AuthorizationDataEntry> authorizationDataEntries, KerberosKey kerberosKey) throws Kerb4JException {

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
