package com.kerb4j.server.marshall;

import com.kerb4j.server.marshall.pac.Pac;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;

public class TestPac {

    private byte[] rc4Data;
    private byte[] desData;
    private byte[] corruptData;
    private SecretKeySpec rc4Key;
    private SecretKeySpec desKey;
    private SecretKeySpec corruptKey;

    @BeforeEach
    public void setUp() throws IOException {
        InputStream file;
        byte[] keyData;

        file = this.getClass().getClassLoader().getResourceAsStream("rc4-pac-data");
        rc4Data = new byte[file.available()];
        file.read(rc4Data);
        file.close();

        file = this.getClass().getClassLoader().getResourceAsStream("des-pac-data");
        desData = new byte[file.available()];
        file.read(desData);
        file.close();

        corruptData = new byte[]{5, 4, 2, 1, 5, 4, 2, 1, 3};

        file = this.getClass().getClassLoader().getResourceAsStream("rc4-key-data");
        keyData = new byte[file.available()];
        file.read(keyData);
        rc4Key = new SecretKeySpec(keyData, "ArcFourHmac");
        file.close();

        file = this.getClass().getClassLoader().getResourceAsStream("des-key-data");
        keyData = new byte[file.available()];
        file.read(keyData);
        desKey = new SecretKeySpec(keyData, "DES");
        file.close();

        corruptKey = new SecretKeySpec(new byte[]{5, 4, 2, 1, 5, 4, 2, 1, 3}, "");
    }

    @Test
    public void testRc4Pac() {
        try {
            Pac pac = new Pac(rc4Data, rc4Key);

            Assertions.assertNotNull(pac);
            Assertions.assertNotNull(pac.getLogonInfo());

            Assertions.assertEquals("user.test", pac.getLogonInfo().getUserName());
            Assertions.assertEquals("User Test", pac.getLogonInfo().getUserDisplayName());
            Assertions.assertEquals(0, pac.getLogonInfo().getBadPasswordCount());
            Assertions.assertEquals(32, pac.getLogonInfo().getUserFlags());
            Assertions.assertEquals(46, pac.getLogonInfo().getLogonCount());
            Assertions.assertEquals("DOMAIN", pac.getLogonInfo().getDomainName());
            Assertions.assertEquals("WS2008", pac.getLogonInfo().getServerName());

        } catch (Kerb4JException e) {
            e.printStackTrace();
            Assertions.fail(e.getMessage());
        }
    }

    @Test
    public void testDesPac() {
        try {
            Pac pac = new Pac(desData, desKey);

            Assertions.assertNotNull(pac);
            Assertions.assertNotNull(pac.getLogonInfo());

            Assertions.assertEquals("user.test", pac.getLogonInfo().getUserName());
            Assertions.assertEquals("User Test", pac.getLogonInfo().getUserDisplayName());
            Assertions.assertEquals(0, pac.getLogonInfo().getBadPasswordCount());
            Assertions.assertEquals(32, pac.getLogonInfo().getUserFlags());
            Assertions.assertEquals(48, pac.getLogonInfo().getLogonCount());
            Assertions.assertEquals("DOMAIN", pac.getLogonInfo().getDomainName());
            Assertions.assertEquals("WS2008", pac.getLogonInfo().getServerName());

        } catch (Kerb4JException e) {
            e.printStackTrace();
            Assertions.fail(e.getMessage());
        }
    }

    @Test
    public void testCorruptPac() {
        Pac pac = null;
        try {
            pac = new Pac(corruptData, rc4Key);
            Assertions.fail("Should have thrown Kerb4JException.");
        } catch (Kerb4JException e) {
            Assertions.assertNotNull(e);
            Assertions.assertNull(pac);
        }
    }

    @Test
    public void testEmptyPac() {
        Pac pac = null;
        try {
            pac = new Pac(new byte[0], rc4Key);
            Assertions.fail("Should have thrown Kerb4JException.");
        } catch (Kerb4JException e) {
            Assertions.assertNotNull(e);
            Assertions.assertNull(pac);
        }
    }

    @Test
    public void testNullPac() {
        Pac pac = null;
        try {
            pac = new Pac(null, rc4Key);
            Assertions.fail("Should have thrown NullPointerException.");
        } catch (Kerb4JException e) {
            e.printStackTrace();
            Assertions.fail(e.getMessage());
        } catch (NullPointerException e) {
            Assertions.assertNotNull(e);
            Assertions.assertNull(pac);
        }
    }

    @Test
    public void testCorruptKey() {
        Pac pac = null;
        try {
            pac = new Pac(rc4Data, corruptKey);
            Assertions.fail("Should have thrown Kerb4JException.");
        } catch (Kerb4JException e) {
            Assertions.assertNotNull(e);
            Assertions.assertNull(pac);
        }
    }
}
