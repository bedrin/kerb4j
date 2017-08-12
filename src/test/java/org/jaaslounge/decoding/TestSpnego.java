package org.jaaslounge.decoding;

import java.io.IOException;
import java.io.InputStream;

import org.jaaslounge.decoding.kerberos.KerberosAuthData;
import org.jaaslounge.decoding.kerberos.KerberosPacAuthData;
import org.jaaslounge.decoding.kerberos.KerberosToken;
import org.jaaslounge.decoding.pac.PacLogonInfo;
import org.jaaslounge.decoding.spnego.SpnegoConstants;
import org.jaaslounge.decoding.spnego.SpnegoInitToken;
import org.jaaslounge.decoding.spnego.SpnegoToken;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import javax.security.auth.kerberos.KerberosKey;

import static org.junit.Assert.assertNotNull;
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
            SpnegoToken spnegoToken = SpnegoToken.parse(rc4Token);

            Assert.assertNotNull(spnegoToken);
            Assert.assertTrue(spnegoToken instanceof SpnegoInitToken);
            Assert.assertNotNull(spnegoToken.getMechanismToken());
            Assert.assertTrue(spnegoToken.getMechanismToken().length < rc4Token.length);
            Assert.assertNotNull(spnegoToken.getMechanism());
            Assert.assertEquals(SpnegoConstants.LEGACY_KERBEROS_MECHANISM, spnegoToken.getMechanism());
        } catch(DecodingException e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

    @Test
    public void testDesToken() {
        try {
            SpnegoToken spnegoToken = SpnegoToken.parse(desToken);

            Assert.assertNotNull(spnegoToken);
            Assert.assertTrue(spnegoToken instanceof SpnegoInitToken);
            Assert.assertNotNull(spnegoToken.getMechanismToken());
            Assert.assertTrue(spnegoToken.getMechanismToken().length < desToken.length);
            Assert.assertNotNull(spnegoToken.getMechanism());
            Assert.assertEquals(SpnegoConstants.LEGACY_KERBEROS_MECHANISM, spnegoToken.getMechanism());
        } catch(DecodingException e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

    @Test
    public void testAes128Token() {
        try {
            SpnegoToken spnegoToken = SpnegoToken.parse(aes128Token);

            Assert.assertNotNull(spnegoToken);
            Assert.assertTrue(spnegoToken instanceof SpnegoInitToken);
            Assert.assertNotNull(spnegoToken.getMechanismToken());
            Assert.assertTrue(spnegoToken.getMechanismToken().length < aes128Token.length);
            Assert.assertNotNull(spnegoToken.getMechanism());
            Assert.assertEquals(SpnegoConstants.LEGACY_KERBEROS_MECHANISM, spnegoToken.getMechanism());
        } catch(DecodingException e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

    @Test
    public void testAes256Token() throws DecodingException {

        SpnegoToken spnegoToken = SpnegoToken.parse(aes256Token);

        Assert.assertNotNull(spnegoToken);
        Assert.assertTrue(spnegoToken instanceof SpnegoInitToken);
        Assert.assertNotNull(spnegoToken.getMechanismToken());
        Assert.assertTrue(spnegoToken.getMechanismToken().length < aes256Token.length);
        Assert.assertNotNull(spnegoToken.getMechanism());
        Assert.assertEquals(SpnegoConstants.LEGACY_KERBEROS_MECHANISM, spnegoToken.getMechanism());

        byte[] kerberosTokenData = spnegoToken.getMechanismToken();

        KerberosToken token = new KerberosToken(kerberosTokenData, aes256Keys);
        for (KerberosAuthData authData : token.getTicket().getEncData().getUserAuthorizations()) {
            if (authData instanceof KerberosPacAuthData) {
                PacLogonInfo logonInfo = ((KerberosPacAuthData) authData).getPac().getLogonInfo();
                assertNotNull(logonInfo);
            } else {
                fail();
            }
        }

    }

    @Test
    public void testEmptyToken() {
        SpnegoToken spnegoToken = null;
        try {
            spnegoToken = SpnegoToken.parse(new byte[0]);
            fail("Should have thrown DecodingException.");
        } catch(DecodingException e) {
            Assert.assertNotNull(e);
            Assert.assertNull(spnegoToken);
        }
    }

    @Test
    public void testCorruptToken() {
        SpnegoToken spnegoToken = null;
        try {
            spnegoToken = SpnegoToken.parse(corruptToken);
            fail("Should have thrown DecodingException.");
        } catch(DecodingException e) {
            Assert.assertNotNull(e);
            Assert.assertNull(spnegoToken);
        }
    }

    @Test
    public void testNullToken() {
        SpnegoToken spnegoToken = null;
        try {
            spnegoToken = SpnegoToken.parse(null);
            fail("Should have thrown NullPointerException.");
        } catch(DecodingException e) {
            e.printStackTrace();
            fail(e.getMessage());
        } catch(NullPointerException e) {
            Assert.assertNotNull(e);
            Assert.assertNull(spnegoToken);
        }
    }

}
