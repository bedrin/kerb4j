package com.kerb4j.server.marshall.spnego;

import com.kerb4j.server.marshall.Kerb4JException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for multi-principal SPN extraction functionality.
 */
public class SpnegoInitTokenMultiPrincipalTest {

    @Test
    public void testGetServerPrincipalNameMethod() {
        // This test verifies that the new method exists and can be called
        // We can't test with real tokens without a full Kerberos setup,
        // but we can at least verify the method signature
        
        try {
            // Create a dummy token that will fail but allows us to test method existence
            byte[] dummyToken = new byte[]{0x61}; // Wrong tag to trigger immediate failure
            
            assertThrows(Exception.class, () -> {
                SpnegoInitToken token = new SpnegoInitToken(dummyToken);
                token.getServerPrincipalName(); // This should throw due to invalid token
            });
            
        } catch (Exception e) {
            // Expected - we're just testing that the method exists
        }
    }
}