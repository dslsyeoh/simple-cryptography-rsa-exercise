package com.dsl.simple.cryptography.utils;


import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public final class Crypto
{
    private static byte[] publicKey;
    private static byte[] privateKey;

    private static final String ALGORITHM = "RSA";
    
    public static void setPublicKey(byte[] publicKey)
    {
        Crypto.publicKey = publicKey;
    }

    public static void setPrivateKey(byte[] privateKey)
    {
        Crypto.privateKey = privateKey;
    }

    public static String encrypt(String text)
    {
        try
        {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);

            PublicKey publicKey = keyFactory.generatePublic(keySpec);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            byte[] data = text.getBytes(StandardCharsets.UTF_8);
            byte[] encrypted = cipher.doFinal(data);

            return Base64.getEncoder().encodeToString(encrypted);

        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e)
        {
            e.printStackTrace();
        }
        return null;
    }

    public static String decrypt(String encryptedString)
    {
        try
        {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);

            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            byte[] data = Base64.getDecoder().decode(encryptedString.getBytes(StandardCharsets.UTF_8));
            byte[] decrypted = cipher.doFinal(data);

            return new String(decrypted, StandardCharsets.UTF_8);

        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e)
        {
            e.printStackTrace();
        }

        return null;
    }

}
