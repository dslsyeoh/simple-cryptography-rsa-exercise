package com.dsl.simple.cryptography.utils;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class KeyGenerator
{
    private final static String ALGORITHM = "RSA";

    public void generateRSAKey()
    {
        try
        {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            File publicKeyFile = makeDir("security/publicKey");
            File privateKeyFile  = makeDir("security/privateKey");

            writeKeyPairToFile(publicKeyFile, keyPair.getPublic().getEncoded());
            writeKeyPairToFile(privateKeyFile, keyPair.getPrivate().getEncoded());
        }
        catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        }
    }

    private void writeKeyPairToFile(File file, byte[] data)
    {
        try(FileOutputStream fileOutputStream = new FileOutputStream(file))
        {
            fileOutputStream.write(data);
            fileOutputStream.flush();
        }
        catch (IOException e)
        {
            e.printStackTrace();
        }
    }

    private File makeDir(String filePath)
    {
        File file = new File(filePath);
        if (!file.exists())
        {
            file.getParentFile().mkdir();
        }
        return file;
    }
}
