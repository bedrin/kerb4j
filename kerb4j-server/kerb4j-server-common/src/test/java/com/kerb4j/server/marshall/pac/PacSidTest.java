package com.kerb4j.server.marshall.pac;

import com.kerb4j.server.marshall.Kerb4JException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class PacSidTest {

    @Test
    void equalsAndHashCodeUseSidValue() throws Kerb4JException {
        PacSid sidA = PacSid.createFromSubs(new byte[]{0x15, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04});
        PacSid sidB = PacSid.createFromSubs(new byte[]{0x15, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04});
        PacSid sidC = PacSid.createFromSubs(new byte[]{0x15, 0x00, 0x00, 0x00, 0x05, 0x06, 0x07, 0x08});

        Assertions.assertEquals(sidA, sidB);
        Assertions.assertEquals(sidA.hashCode(), sidB.hashCode());
        Assertions.assertNotEquals(sidA, sidC);
    }
}
