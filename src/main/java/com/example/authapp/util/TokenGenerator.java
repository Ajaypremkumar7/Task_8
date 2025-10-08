package com.example.authapp.util;

import org.apache.commons.lang3.RandomStringUtils;

public class TokenGenerator {

    public static String generateToken(int length) {
        return RandomStringUtils.randomAlphanumeric(length);
    }
}
