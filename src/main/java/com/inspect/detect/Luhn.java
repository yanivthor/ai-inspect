package com.inspect.detect;

/**
 * The Luhn checksum every payment card number satisfies. A bare "13-19 digits" regex matches
 * order numbers, tracking ids and phone numbers; requiring the check digit removes roughly
 * nine in ten of those, which is the cheapest precision available anywhere in this project.
 */
final class Luhn {
    private Luhn() {}

    static boolean isValid(String digits) {
        if (digits.isEmpty()) return false;
        int sum = 0;
        boolean doubleIt = false;
        for (int i = digits.length() - 1; i >= 0; i--) {
            int d = digits.charAt(i) - '0';
            if (d < 0 || d > 9) return false;
            if (doubleIt) {
                d *= 2;
                if (d > 9) d -= 9;
            }
            sum += d;
            doubleIt = !doubleIt;
        }
        return sum % 10 == 0;
    }
}
