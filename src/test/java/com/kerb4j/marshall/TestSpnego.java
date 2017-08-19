package com.kerb4j.marshall;

import com.kerb4j.marshall.Kerb4JException;
import com.kerb4j.marshall.pac.Pac;
import com.kerb4j.marshall.pac.PacLogonInfo;
import com.kerb4j.marshall.pac.PacSid;
import com.kerb4j.marshall.spnego.SpnegoConstants;
import com.kerb4j.marshall.spnego.SpnegoInitToken;
import com.kerb4j.marshall.spnego.SpnegoKerberosMechToken;
import org.apache.kerby.kerberos.kerb.KrbCodec;
import org.apache.kerby.kerberos.kerb.crypto.EncryptionHandler;
import org.apache.kerby.kerberos.kerb.type.ad.AuthorizationData;
import org.apache.kerby.kerberos.kerb.type.ad.AuthorizationDataEntry;
import org.apache.kerby.kerberos.kerb.type.base.EncryptedData;
import org.apache.kerby.kerberos.kerb.type.base.KeyUsage;
import org.apache.kerby.kerberos.kerb.type.ticket.EncTicketPart;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import javax.security.auth.kerberos.KerberosKey;
import java.io.IOException;
import java.io.InputStream;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class TestSpnego {

    private byte[] rc4Token;
    private byte[] desToken;
    private byte[] aes128Token;
    private byte[] aes256Token;
    private byte[] corruptToken;

    private KerberosKey aes256Keys[];


    @Before
    public void setUp() throws IOException {
        InputStream file;

        file = this.getClass().getClassLoader().getResourceAsStream("rc4-spnego-data");
        rc4Token = new byte[file.available()];
        file.read(rc4Token);
        file.close();

        file = this.getClass().getClassLoader().getResourceAsStream("des-spnego-data");
        desToken = new byte[file.available()];
        file.read(desToken);
        file.close();

        file = this.getClass().getClassLoader().getResourceAsStream("aes128-spnego-data");
        aes128Token = new byte[file.available()];
        file.read(aes128Token);
        file.close();

        file = this.getClass().getClassLoader().getResourceAsStream("aes256-spnego-data");
        aes256Token = new byte[file.available()];
        file.read(aes256Token);
        file.close();

        byte[] keyData;
        file = this.getClass().getClassLoader().getResourceAsStream("aes256-key-data");
        keyData = new byte[file.available()];
        file.read(keyData);
        aes256Keys = new KerberosKey[]{new KerberosKey(null, keyData, 18, 2)};
        file.close();

        corruptToken = new byte[]{5, 4, 2, 1};
    }

    @Test
    public void testRc4Token() {
        try {
            SpnegoInitToken spnegoToken = new SpnegoInitToken(rc4Token);

            Assert.assertNotNull(spnegoToken);
            assertTrue(spnegoToken instanceof SpnegoInitToken);
            Assert.assertNotNull(spnegoToken.getMechToken());
            assertTrue(spnegoToken.getMechToken().length < rc4Token.length);
            Assert.assertNotNull(spnegoToken.getMechanism());
            Assert.assertEquals(SpnegoConstants.LEGACY_KERBEROS_MECHANISM, spnegoToken.getMechanism());
        } catch(Kerb4JException e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

    @Test
    public void testDesToken() {
        try {
            SpnegoInitToken spnegoToken = new SpnegoInitToken(desToken);

            Assert.assertNotNull(spnegoToken);
            assertTrue(spnegoToken instanceof SpnegoInitToken);
            Assert.assertNotNull(spnegoToken.getMechToken());
            assertTrue(spnegoToken.getMechToken().length < desToken.length);
            Assert.assertNotNull(spnegoToken.getMechanism());
            Assert.assertEquals(SpnegoConstants.LEGACY_KERBEROS_MECHANISM, spnegoToken.getMechanism());
        } catch(Kerb4JException e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

    @Test
    public void testAes128Token() {
        try {
            SpnegoInitToken spnegoToken = new SpnegoInitToken(aes128Token);

            Assert.assertNotNull(spnegoToken);
            assertTrue(spnegoToken instanceof SpnegoInitToken);
            Assert.assertNotNull(spnegoToken.getMechToken());
            assertTrue(spnegoToken.getMechToken().length < aes128Token.length);
            Assert.assertNotNull(spnegoToken.getMechanism());
            Assert.assertEquals(SpnegoConstants.LEGACY_KERBEROS_MECHANISM, spnegoToken.getMechanism());
        } catch(Kerb4JException e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

    @Test
    public void testAes256Token() throws Kerb4JException {

        SpnegoInitToken spnegoToken = new SpnegoInitToken(aes256Token);

        Assert.assertNotNull(spnegoToken);
        assertTrue(spnegoToken instanceof SpnegoInitToken);
        Assert.assertNotNull(spnegoToken.getMechToken());
        assertTrue(spnegoToken.getMechToken().length < aes256Token.length);
        Assert.assertNotNull(spnegoToken.getMechanism());
        Assert.assertEquals(SpnegoConstants.LEGACY_KERBEROS_MECHANISM, spnegoToken.getMechanism());

        byte[] kerberosTokenData = spnegoToken.getMechToken();

        SpnegoKerberosMechToken token = new SpnegoKerberosMechToken(kerberosTokenData, aes256Keys);

        try {

            EncryptedData encryptedData = token.getApRequest().getTicket().getEncryptedEncPart();

            byte[] decrypt = EncryptionHandler.getEncHandler(aes256Keys[0].getKeyType()).decrypt(
                    encryptedData.getCipher(),
                    aes256Keys[0].getEncoded(),
                    KeyUsage.KDC_REP_TICKET.getValue()
            );
            EncTicketPart tgsRep = KrbCodec.decode(decrypt, EncTicketPart.class);
            System.out.println(tgsRep);

            AuthorizationDataEntry authorizationDataEntry = tgsRep.getAuthorizationData().getElements().get(0);

            Pac pac = null;
            while (null == pac) {
                switch (authorizationDataEntry.getAuthzType()) {
                    case AD_IF_RELEVANT:
                        authorizationDataEntry = authorizationDataEntry.getAuthzDataAs(AuthorizationData.class).getElements().get(0);
                        continue;
                    case AD_WIN2K_PAC:
                        pac = new Pac(authorizationDataEntry.getAuthzData(), aes256Keys[0]);
                }
            }

            PacLogonInfo logonInfo = pac.getLogonInfo();
            assertNotNull(logonInfo);
            assertNotNull(logonInfo.getGroupSids());

            boolean found = false;

            for (PacSid groupSid : logonInfo.getGroupSids()) {
                if ("S-1-5-21-4028881986-3284141023-698984075-513".equals(groupSid.toHumanReadableString())) {
                    found = true;
                }
            }

            assertTrue(found);


        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    @Test
    public void testEmptyToken() {
        SpnegoInitToken spnegoToken = null;
        try {
            spnegoToken = new SpnegoInitToken(new byte[0]);
            fail("Should have thrown Kerb4JException.");
        } catch(Kerb4JException e) {
            Assert.assertNotNull(e);
            Assert.assertNull(spnegoToken);
        }
    }

    @Test
    public void testCorruptToken() {
        SpnegoInitToken spnegoToken = null;
        try {
            spnegoToken = new SpnegoInitToken(corruptToken);
            fail("Should have thrown Kerb4JException.");
        } catch(Kerb4JException e) {
            Assert.assertNotNull(e);
            Assert.assertNull(spnegoToken);
        }
    }

    @Test
    public void testNullToken() {
        SpnegoInitToken spnegoToken = null;
        try {
            spnegoToken = new SpnegoInitToken(null);
            fail("Should have thrown NullPointerException.");
        } catch(Kerb4JException e) {
            e.printStackTrace();
            fail(e.getMessage());
        } catch(NullPointerException e) {
            Assert.assertNotNull(e);
            Assert.assertNull(spnegoToken);
        }
    }

}
