package com.xpresspayments.GTCollection.gt_collections.services;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA512Generator {

    public static String encrypt(String passwordToHash) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        String generatedPassword;

        MessageDigest md = MessageDigest.getInstance("SHA-512");
        byte[] bytes = md.digest(passwordToHash.getBytes("UTF-8"));
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
        }
        generatedPassword = sb.toString();

        return generatedPassword;
    }
}
