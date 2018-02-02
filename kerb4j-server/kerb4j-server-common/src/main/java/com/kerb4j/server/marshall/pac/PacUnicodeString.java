package com.kerb4j.server.marshall.pac;

import com.kerb4j.server.marshall.Kerb4JException;

public class PacUnicodeString {

    private short length;
    private short maxLength;
    private int pointer;

    public PacUnicodeString(short length, short maxLength, int pointer) {
        super();
        this.length = length;
        this.maxLength = maxLength;
        this.pointer = pointer;
    }

    public short getLength() {
        return length;
    }

    public short getMaxLength() {
        return maxLength;
    }

    public int getPointer() {
        return pointer;
    }

    public String check(String string) throws Kerb4JException {
        if (pointer == 0 && string != null)
            throw new Kerb4JException("pac.string.notempty", null, null);

        int expected = length / 2;
        if (string.length() != expected) {
            Object[] args = new Object[]{expected, string.length()};
            throw new Kerb4JException("pac.string.invalid.size", args, null);
        }

        return string;
    }
}
