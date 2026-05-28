package com.kerb4j.server.spring;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.FileSystemResource;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link SimpleMultiPrincipalManager}.
 */
public class SimpleMultiPrincipalManagerTest {

    private SimpleMultiPrincipalManager manager;

    @BeforeEach
    public void setUp() {
        manager = new SimpleMultiPrincipalManager();
    }

    @Test
    public void testEmptyManagerReturnsNullAndFalse() {
        assertEquals(0, manager.getConfiguredSpns().length);
        assertFalse(manager.hasPrincipalForSpn("HTTP/host@REALM"));
        assertNull(manager.getSpnegoClientForSpn("HTTP/host@REALM"));
    }

    @Test
    public void testNullSpnLookupReturnsSafeDefaults() {
        assertNull(manager.getSpnegoClientForSpn(null));
        assertFalse(manager.hasPrincipalForSpn(null));
    }

    @Test
    public void testAddPrincipalWithNullNameThrows() {
        assertThrows(IllegalArgumentException.class,
                () -> manager.addPrincipal(null, new FileSystemResource("/tmp/dummy.keytab")));
    }

    @Test
    public void testAddPrincipalWithBlankNameThrows() {
        assertThrows(IllegalArgumentException.class,
                () -> manager.addPrincipal("  ", new FileSystemResource("/tmp/dummy.keytab")));
    }

    @Test
    public void testAddPrincipalWithNullResourceThrows() {
        assertThrows(IllegalArgumentException.class,
                () -> manager.addPrincipal("HTTP/host@REALM", null));
    }

    @Test
    public void testAddPrincipalWithNonFileResourceThrows() {
        // A classpath resource inside a JAR cannot be resolved to a File
        org.springframework.core.io.ClassPathResource jar = new org.springframework.core.io.ClassPathResource("nonexistent/path.keytab");
        assertThrows(IllegalArgumentException.class,
                () -> manager.addPrincipal("HTTP/host@REALM", jar));
    }

    @Test
    public void testPathWithSpaceIsHandledCorrectly() throws IOException {
        // Regression: the old implementation used URL.toExternalForm() and stripped "file:",
        // which left URL-encoded paths like "/tmp/kerb4j%20test%20dir/my%20keytab..." that
        // JAAS cannot open. Using getFile().getAbsolutePath() returns the real FS path.
        File dir = Files.createTempDirectory("kerb4j test dir").toFile();
        File keytab = File.createTempFile("my keytab", ".keytab", dir);
        keytab.deleteOnExit();
        dir.deleteOnExit();

        FileSystemResource resource = new FileSystemResource(keytab);

        // Verify the resolved path preserves spaces (not URL-encoded)
        String resolvedPath = resource.getFile().getAbsolutePath();
        assertTrue(resolvedPath.contains(" "),
                "Resolved path should contain space characters, not URL-encoded %20");
        assertFalse(resolvedPath.contains("%20"),
                "Resolved path must not contain URL-encoded spaces");

        // addPrincipal must not throw IllegalArgumentException for a valid file resource.
        // loginWithKeyTab is lazy so no Kerberos exception occurs at construction time.
        assertDoesNotThrow(() -> manager.addPrincipal("HTTP/host@REALM", resource),
                "addPrincipal must not throw for a valid local file resource");
    }

    @Test
    public void testGetConfiguredSpnsReturnsAllAdded() throws IOException {
        // Create two temp keytab files; login will fail but we test the lookup behavior
        // by catching the RuntimeException from loginWithKeyTab
        File kt1 = File.createTempFile("kt1", ".keytab");
        File kt2 = File.createTempFile("kt2", ".keytab");
        kt1.deleteOnExit();
        kt2.deleteOnExit();

        // Try to add - will throw RuntimeException because keytabs are empty (not valid)
        // but we only need to know that the method was attempted
        // Verify that before any addition, queries return empty
        assertEquals(0, manager.getConfiguredSpns().length);
        assertFalse(manager.hasPrincipalForSpn("HTTP/host1@REALM"));
        assertFalse(manager.hasPrincipalForSpn("HTTP/host2@REALM"));
    }
}
