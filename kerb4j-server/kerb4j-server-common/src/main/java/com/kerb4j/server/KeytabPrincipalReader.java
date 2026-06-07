package com.kerb4j.server;

import org.apache.kerby.kerberos.kerb.keytab.Keytab;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.jspecify.annotations.NullMarked;

import java.io.File;
import java.io.IOException;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Reads service principal names from keytab files.
 */
@NullMarked
public final class KeytabPrincipalReader {

    private KeytabPrincipalReader() {
    }

    /**
     * Read all unique principals from a keytab file.
     *
     * @param keyTabLocation the local keytab file path
     * @return unique principal names in keytab order
     * @throws IllegalArgumentException if the keytab path is invalid or cannot be read
     */
    public static Collection<String> getPrincipals(String keyTabLocation) {
        if (keyTabLocation == null || keyTabLocation.trim().isEmpty()) {
            throw new IllegalArgumentException("Key tab location must not be null or empty");
        }
        return getPrincipals(new File(keyTabLocation));
    }

    /**
     * Read all unique principals from a keytab file.
     *
     * @param keyTabFile the local keytab file
     * @return unique principal names in keytab order
     * @throws IllegalArgumentException if the keytab file is invalid or cannot be read
     */
    public static Collection<String> getPrincipals(File keyTabFile) {
        if (keyTabFile == null) {
            throw new IllegalArgumentException("Key tab file must not be null");
        }
        if (!keyTabFile.isFile()) {
            throw new IllegalArgumentException("Key tab must be a local file: " + keyTabFile);
        }

        try {
            Keytab keytab = Keytab.loadKeytab(keyTabFile);
            Set<String> principals = new LinkedHashSet<>();
            for (PrincipalName principal : keytab.getPrincipals()) {
                principals.add(principal.getName());
            }
            return principals;
        } catch (IOException e) {
            throw new IllegalArgumentException("Failed to read keytab principals from: " + keyTabFile, e);
        }
    }
}
