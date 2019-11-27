package com.dsl.simple.cryptography;

import com.dsl.simple.cryptography.utils.Crypto;
import com.dsl.simple.cryptography.utils.KeyGenerator;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Objects;

public class Main
{
    public static void main(String[] args)
    {
        KeyGenerator keyGenerator = new KeyGenerator();
        keyGenerator.generateRSAKey();

        try
        {
            byte[] publicKey = Files.readAllBytes(Paths.get("security", "publicKey"));
            byte[] privateKey = Files.readAllBytes(Paths.get("security","privateKey"));

            Crypto.setPublicKey(publicKey);
            Crypto.setPrivateKey(privateKey);

            String encryptedString = Crypto.encrypt("This is confidential text");
            if(Objects.nonNull(encryptedString))
            {
                System.out.println("Encrypted: " + encryptedString);
                String decryptedString = Crypto.decrypt(encryptedString);
                System.out.println("Decrypted: " + decryptedString);
            }
        }
        catch (IOException e)
        {
            e.printStackTrace();
        }
    }
}
