package com.inspect.detect;

import java.math.BigInteger;

/** ISO 13616 mod-97 check. Same reasoning as {@link Luhn}: a checksum is free precision. */
final class Iban {
    private Iban() {}

    static boolean isValid(String compact) {
        if (compact.length() < 15 || compact.length() > 34) return false;
        String rearranged = compact.substring(4) + compact.substring(0, 4);
        StringBuilder numeric = new StringBuilder(rearranged.length() * 2);
        for (int i = 0; i < rearranged.length(); i++) {
            char c = rearranged.charAt(i);
            if (c >= '0' && c <= '9') numeric.append(c);
            else if (c >= 'A' && c <= 'Z') numeric.append(c - 'A' + 10);
            else return false;
        }
        return new BigInteger(numeric.toString()).mod(BigInteger.valueOf(97)).intValue() == 1;
    }
}
