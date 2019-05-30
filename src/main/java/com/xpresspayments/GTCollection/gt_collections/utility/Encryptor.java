package com.xpresspayments.GTCollection.gt_collections.utility;

/**
 * Created by oluwafemi.shobowale on 10/27/2018.
 */

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.*;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;
import java.util.HashMap;
import java.util.Map;


public class Encryptor {

    public static final String ENCODING_UTF8 = "UTF8";
    public static final String ALGORITHM_DESede = "DESede";
    public static final String ALGORITHM_AES = "AES";
    public static final String TRANSFORMATION_DESede_ECB_PKCS5Padding = "DESede/ECB/PKCS5Padding";
    public static final String TRANSFORMATION_DESede_CBC_PKC5Padding = "DESede/CBC/PKCS5Padding";
    public static final String TRANSFORMATION_AES_CBC_PKCS5PADDING = "AES/CBC/PKCS5PADDING";
    public static final String TRANSFORMATION_AES_ECB_PKCS7PADDING = "AES/ECB/PKCS7PADDING";
    public static final String TRANSFORMATION_AES = "AES";

    private static final Map<String, String> transformationMap = new HashMap<String, String>();
    static {
        transformationMap.put(TRANSFORMATION_DESede_CBC_PKC5Padding, ALGORITHM_DESede);
        transformationMap.put(TRANSFORMATION_DESede_ECB_PKCS5Padding, ALGORITHM_DESede);
        transformationMap.put(TRANSFORMATION_AES, ALGORITHM_AES);
        transformationMap.put(TRANSFORMATION_AES_CBC_PKCS5PADDING, ALGORITHM_AES);
        transformationMap.put(TRANSFORMATION_AES_ECB_PKCS7PADDING, ALGORITHM_AES);
    }

    private String transformation;
    private final SecretKey secretKey;
    private IvParameterSpec ivParam;

    public Encryptor(String transformation, byte[] bytesKey, byte[] ivBytes) {
        init(transformation, ivBytes);
        secretKey = new SecretKeySpec(bytesKey, transformationMap.get(transformation));
    }

    public Encryptor (String transformation, SecretKey secretKey, byte[] ivBytes) {
        init(transformation, ivBytes);
        this.secretKey = secretKey;
    }

    private void init(String transformation, byte[] ivBytes) {
        this.transformation = transformation;
        if (ivBytes != null) {
            ivParam = new IvParameterSpec(ivBytes);
        }
    }

    public static SecretKey generateKey(String algorithm) throws NoSuchAlgorithmException {
        KeyGenerator keygen = KeyGenerator.getInstance(algorithm);
        return keygen.generateKey();
    }

    // Confirm later
    public static SecretKey getKey(String keyInput, String algorithm) throws GeneralSecurityException, UnsupportedEncodingException {
        byte[] keyBytes = keyInput.getBytes("ASCII");
        DESedeKeySpec keySpec = new DESedeKeySpec(keyBytes);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm);
        return factory.generateSecret(keySpec);
    }

    public static String getBase64StringFromKey(SecretKey key) {
        byte[] keyBytes = key.getEncoded();
        return new BASE64Encoder().encode(keyBytes);
    }

    public static SecretKey getKeyFromBase64String(String base64StringKey, String algorithm) throws IOException {
        byte[] keyBytes = new BASE64Decoder().decodeBuffer(base64StringKey);
        return new SecretKeySpec(keyBytes, algorithm);
    }

    public static SecretKeySpec getKeyFromBytes(byte[] bytes, String algorithm) {
        return new SecretKeySpec(bytes, algorithm);
    }

    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public byte[] encrypt(byte[] clearBytes) throws InvalidKeyException, BadPaddingException, NoSuchPaddingException,
            IllegalBlockSizeException, NoSuchAlgorithmException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
        return getCipher(Cipher.ENCRYPT_MODE).doFinal(clearBytes);
    }

    public byte[] decrypt(byte[] cipherBytes) throws InvalidKeyException, BadPaddingException,
            IllegalBlockSizeException, NoSuchPaddingException, UnsupportedEncodingException, IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        return getCipher(Cipher.DECRYPT_MODE).doFinal(cipherBytes);
    }

    private Cipher getCipher(int cipherMode) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance(transformation);
        if (ivParam != null) {
            cipher.init(cipherMode, secretKey, ivParam);
        } else {
            cipher.init(cipherMode, secretKey);
        }
        return cipher;
    }

    public String decryptBase64(String base64CipherText) throws InvalidKeyException, BadPaddingException,
            IllegalBlockSizeException, NoSuchPaddingException, UnsupportedEncodingException, IOException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] cipherBytes = new BASE64Decoder().decodeBuffer(base64CipherText);
        byte[] clearBytes = cipher.doFinal(cipherBytes);
        return new String(clearBytes, ENCODING_UTF8);
    }

    byte[] binaryToByteArray(String binaryStr) {
        int sLen = binaryStr.length();
        byte[] toReturn = new byte[(sLen + Byte.SIZE - 1) / Byte.SIZE];
        char c;
        for( int i = 0; i < sLen; i++ ) {
            if( (c = binaryStr.charAt(i)) == '1' ) {
                toReturn[i / Byte.SIZE] = (byte) (toReturn[i / Byte.SIZE] | (0x80 >>> (i % Byte.SIZE)));
            } else if ( c != '0' ) {
                throw new IllegalArgumentException();
            }
        }
        return toReturn;
    }

    public static String byteArrayToBinary(byte[] byteArray) {
        StringBuilder sb = new StringBuilder(byteArray.length * Byte.SIZE);
        for( int i = 0; i < Byte.SIZE * byteArray.length; i++ ) {
            sb.append((byteArray[i / Byte.SIZE] << i % Byte.SIZE & 0x80) == 0 ? '0' : '1');
        }
        return sb.toString();
    }

    public static byte[] stringToByteArray2(String binaryStr) {
        return new BigInteger(binaryStr, 2).toByteArray();
    }

    public static SecretKey getKeyFromBytes(byte[] bytes) throws Exception {
        DESedeKeySpec keySpec = new DESedeKeySpec(bytes);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM_DESede);
        return factory.generateSecret(keySpec);
    }

    public SecretKey getSecretKey() {
        return secretKey;
    }

    public static void main(String[] args) throws Exception {
//        testTripleDES_ECB();
//        testTripleDES_CBC();
//        testAES_CBC();
//        testAES_CBC();
        testHeritageEncryption();
    }

    public static String getSHA512(String passwordToHash) throws UnsupportedEncodingException{
        String generatedPassword = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            byte[] bytes = md.digest(passwordToHash.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for(int i=0; i< bytes.length ;i++){
                sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
            }
            generatedPassword = sb.toString();
        } catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }
        return generatedPassword;
    }

    public static void testTripleDES_ECB() throws Exception {
        SecretKey secretKey = Encryptor.generateKey(ALGORITHM_DESede);
        System.out.println("Base64EncodedKey: " + Encryptor.getBase64StringFromKey(secretKey));
        System.out.println("Key Length: " + secretKey.getEncoded().length);
        Encryptor encryptor = new Encryptor (Encryptor.TRANSFORMATION_DESede_ECB_PKCS5Padding, secretKey, null);

        String clearText = "Hello Cryptography!";
        System.out.println("Clear Text: " + clearText);
        String base64CipherText = new BASE64Encoder().encode(encryptor.encrypt(clearText.getBytes()));
        System.out.println("Base64 Cipher Text: " + base64CipherText);
        String decodedClearText = encryptor.decryptBase64(base64CipherText);
        System.out.println("Decoded Clear Text: " + decodedClearText);
    }

    public static void testTripleDES_CBC() throws Exception {
        String ivBinaryStr = "0000000100000010000000110000010100000111000010110000110100010001";
        String keyStr = "000000010000001000000011000001010000011100001011000011010001000100010010000100010000110100001011000001110000001000000100000010000000000100000010000000110000010100000111000010110000110100010001";
        String clearText = "<?xml version='1.0' encoding='UTF-8'?><Request><T24UserName>abubakarln</T24UserName><Token>abubakarlnpwd</Token></Request>";

        byte[] keyBytes = stringToByteArray2(keyStr);
        byte[] ivBytes = stringToByteArray2(ivBinaryStr);
        Encryptor encryptor = new Encryptor(TRANSFORMATION_DESede_CBC_PKC5Padding, keyBytes, ivBytes);
        byte[] cipherBytes = encryptor.encrypt(clearText.getBytes());
        System.out.println(">>> Result: " + new BASE64Encoder().encode(cipherBytes));
    }

    public static void testAES_CBC() throws Exception {
        String clearText = "<QuerySingleDebitMultipleCreditRequest> \n" +
                "<ClientAuthentication>\n" +
                "<UserID>ndubisi.ekeh</UserID> \n" +
                "<Username>ndubisi.ekeh</Username> \n" +
                "<Password>XPRSSCON#4567#</Password>\n" +
                "<OTPReference>846FF7</OTPReference> \n" +
                "</ClientAuthentication> \n" +
                "<TransactionQueryRequest>\n" +
                "<TransactionReference>AD|100|56666</TransactionReference>\n" +
                "</TransactionQueryRequest>\n" +
                "</QuerySingleDebitMultipleCreditRequest>";
        String keyStr = ")ExfR%^$$%@H_!DP";
        String iv = "@$%#^%#Hhdg9234B";

        Encryptor encryptor = new Encryptor(TRANSFORMATION_AES_CBC_PKCS5PADDING, keyStr.getBytes(), iv.getBytes());
        byte[] cipherBytes = encryptor.encrypt(clearText.getBytes());
        System.out.println(">>> PostSingleDebitMultipleCredits");
        System.out.println(">>> Result: " + new BASE64Encoder().encode(cipherBytes));
        System.out.println(">>> TransactionHash: " + Encryptor.getSHA512("ndubisi.ekeh846FF7AuthenticationOTPTransactionRequest"));
        System.out.println(">>> QueryHash: " + Encryptor.getSHA512("ndubisi.ekeh846FF7AD|100|56666TransactionRequest")); // Username + OTPReference + TransactionReference + "TransactionRequest"
    }

    private static void testHeritageEncryption() throws Exception {
        byte[] keyBytes = new BASE64Decoder().decodeBuffer("AAECAwQFBgcICQoLDA0ODw==");
        Encryptor encryptor = new Encryptor(Encryptor.TRANSFORMATION_AES_ECB_PKCS7PADDING, keyBytes, null);
        System.out.println(new BASE64Encoder().encode(encryptor.encrypt("testing encryption".getBytes())));
    }

}
