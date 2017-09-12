/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.kerb4j.server;

import java.util.LinkedHashMap;

/**
 * This class implements a hack around an incompatibility between the
 * SPNEGO implementation in Windows and the SPNEGO implementation in Java 8
 * update 40 onwards. It was introduced by the change to fix this bug:
 * https://bugs.openjdk.java.net/browse/JDK-8048194
 * (note: the change applied is not the one suggested in the bug report)
 * <p>
 * It is not clear to me if Windows, Java or Tomcat is at fault here. I
 * think it is Java but I could be wrong.
 * <p>
 * This hack works by re-ordering the list of mechTypes in the NegTokenInit
 * token.
 */
public class SpnegoTokenFixer {

    public static void fix(byte[] token) {
        SpnegoTokenFixer fixer = new SpnegoTokenFixer(token);
        fixer.fix();
    }


    private final byte[] token;
    private int pos = 0;


    private SpnegoTokenFixer(byte[] token) {
        this.token = token;
    }


    // Fixes the token in-place
    private void fix() {
            /*
             * Useful references:
             * http://tools.ietf.org/html/rfc4121#page-5
             * http://tools.ietf.org/html/rfc2743#page-81
             * https://msdn.microsoft.com/en-us/library/ms995330.aspx
             */

        // Scan until we find the mech types list. If we find anything
        // unexpected, abort the fix process.
        if (!tag(0x60)) return;
        if (!length()) return;
        if (!oid("1.3.6.1.5.5.2")) return;
        if (!tag(0xa0)) return;
        if (!length()) return;
        if (!tag(0x30)) return;
        if (!length()) return;
        if (!tag(0xa0)) return;
        lengthAsInt();
        if (!tag(0x30)) return;
        // Now at the start of the mechType list.
        // Read the mechTypes into an ordered set
        int mechTypesLen = lengthAsInt();
        int mechTypesStart = pos;
        LinkedHashMap<String, int[]> mechTypeEntries = new LinkedHashMap<>();
        while (pos < mechTypesStart + mechTypesLen) {
            int[] value = new int[2];
            value[0] = pos;
            String key = oidAsString();
            value[1] = pos - value[0];
            mechTypeEntries.put(key, value);
        }
        // Now construct the re-ordered mechType list
        byte[] replacement = new byte[mechTypesLen];
        int replacementPos = 0;

        int[] first = mechTypeEntries.remove("1.2.840.113554.1.2.2");
        if (first != null) {
            System.arraycopy(token, first[0], replacement, replacementPos, first[1]);
            replacementPos += first[1];
        }
        for (int[] markers : mechTypeEntries.values()) {
            System.arraycopy(token, markers[0], replacement, replacementPos, markers[1]);
            replacementPos += markers[1];
        }

        // Finally, replace the original mechType list with the re-ordered
        // one.
        System.arraycopy(replacement, 0, token, mechTypesStart, mechTypesLen);
    }


    private boolean tag(int expected) {
        return (token[pos++] & 0xFF) == expected;
    }


    private boolean length() {
        // No need to retain the length - just need to consume it and make
        // sure it is valid.
        int len = lengthAsInt();
        return pos + len == token.length;
    }


    private int lengthAsInt() {
        int len = token[pos++] & 0xFF;
        if (len > 127) {
            int bytes = len - 128;
            len = 0;
            for (int i = 0; i < bytes; i++) {
                len = len << 8;
                len = len + (token[pos++] & 0xff);
            }
        }
        return len;
    }


    private boolean oid(String expected) {
        return expected.equals(oidAsString());
    }


    private String oidAsString() {
        if (!tag(0x06)) return null;
        StringBuilder result = new StringBuilder();
        int len = lengthAsInt();
        // First byte is special case
        int v = token[pos++] & 0xFF;
        int c2 = v % 40;
        int c1 = (v - c2) / 40;
        result.append(c1);
        result.append('.');
        result.append(c2);
        int c = 0;
        boolean write = false;
        for (int i = 1; i < len; i++) {
            int b = token[pos++] & 0xFF;
            if (b > 127) {
                b -= 128;
            } else {
                write = true;
            }
            c = c << 7;
            c += b;
            if (write) {
                result.append('.');
                result.append(c);
                c = 0;
                write = false;
            }
        }
        return result.toString();
    }

}
