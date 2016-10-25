/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package x509certificate;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.*;
import javax.crypto.spec.*;

/**
 *
 * @author dijab
 */
public class AESFileEncryption {

    private static final String keyFilePath = "AESKey";
    private Cipher AESCipher;
    private int AESKeySize;
    private byte[] AESKey;

    public AESFileEncryption() {
        try {
            this.AESKeySize = 128;
            // PKCipher = Cipher.getInstance("RSA");
            AESCipher = Cipher.getInstance("AES");
            if ((new File(keyFilePath)).exists()) {
                this.ImportKey();
            } else {
                this.GenerateAESKey();
                this.ExportKey();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public AESFileEncryption(int AESKeySize) {
        try {
            this.AESKeySize = AESKeySize;
            //PKCipher = Cipher.getInstance("RSA");
            AESCipher = Cipher.getInstance("AES");
            if ((new File(keyFilePath)).exists()) {
                this.ImportKey();
            } else {
                this.GenerateAESKey();
                this.ExportKey();
            }
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(AESFileEncryption.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(AESFileEncryption.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void GenerateAESKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(AESKeySize);
            AESKey = keyGen.generateKey().getEncoded();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(AESFileEncryption.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /*   public void GenerateAndExportRSAKeyPAir(String privateKeyFilePath, String publicKeyFilePath) throws NoSuchAlgorithmException, IOException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair keyPair = keyGen.generateKeyPair();

        File privateKeyFile = new File(privateKeyFilePath);
        File publicKeyFile = new File(publicKeyFilePath);

        ObjectOutputStream publicKeyOS = new ObjectOutputStream(new FileOutputStream(publicKeyFile));
        publicKeyOS.writeObject(keyPair.getPublic());
        publicKeyOS.close();

        ObjectOutputStream privateKeyOS = new ObjectOutputStream(new FileOutputStream(privateKeyFile));
        privateKeyOS.writeObject(keyPair.getPrivate());
        privateKeyOS.close();

    }*/
    public void ExportKey() {
        File exportKeyFile = new File(keyFilePath);
        FileOutputStream exportKeyFileOS;
        try {
            exportKeyFileOS = new FileOutputStream(exportKeyFile);
            exportKeyFileOS.write(AESKey);
            exportKeyFileOS.close();
        } catch (FileNotFoundException ex) {
            Logger.getLogger(AESFileEncryption.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(AESFileEncryption.class.getName()).log(Level.SEVERE, null, ex);
        }

        /*File exportKeyFile = new File(exportKeyFilePath);
        File publicKeyFile = new File(publicKeyFilePath);

        ObjectInputStream pkFileInputStream = new ObjectInputStream(new FileInputStream(publicKeyFile));
        PublicKey publicKey = (PublicKey) pkFileInputStream.readObject();

        PKCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        CipherOutputStream cipherOutputStream = new CipherOutputStream(new FileOutputStream(exportKeyFile), PKCipher);
        cipherOutputStream.write(AESKey);
        cipherOutputStream.close();*/
    }

    public void ImportKey(){
        FileInputStream importKeyFileIS = null;
        try {
            File importKeyFile = new File(keyFilePath);
            importKeyFileIS = new FileInputStream(importKeyFile);
            AESKey = new byte[AESKeySize / 8];
            importKeyFileIS.read(AESKey);
            importKeyFileIS.close();
            /*File importKeyFile = new File(importKeyFilePath);
            File publicKeyFile = new File(privateKeyFilePath);
            
            ObjectInputStream pkFileInputStream = new ObjectInputStream(new FileInputStream(publicKeyFile));
            PrivateKey privateKey = (PrivateKey) pkFileInputStream.readObject();
            
            PKCipher.init(Cipher.DECRYPT_MODE, privateKey);
            AESKey = new byte[AESKeySize / 8];
            CipherInputStream cipherInputStream = new CipherInputStream(new FileInputStream(importKeyFile), PKCipher);
            cipherInputStream.read(AESKey);
            AESKeySpec = new SecretKeySpec(AESKey, "AES");*/
        } catch (FileNotFoundException ex) {
            Logger.getLogger(AESFileEncryption.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(AESFileEncryption.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                importKeyFileIS.close();
            } catch (IOException ex) {
                Logger.getLogger(AESFileEncryption.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    public void encrypt(String fileToEncryptPath) {
        try {
            File fileToEncrypt = new File(fileToEncryptPath);
            File encryptedFile = new File("encrypted");
            AESCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(AESKey, "AES"));
            FileInputStream fileToEncryptIS = new FileInputStream(fileToEncrypt);
            CipherOutputStream encryptedFileOS = new CipherOutputStream(new FileOutputStream(encryptedFile), AESCipher);
            byte[] inputBuffer = new byte[1024];
            int len;
            while ((len = fileToEncryptIS.read(inputBuffer)) != -1) {
                encryptedFileOS.write(inputBuffer, 0, len);
            }
            
            fileToEncryptIS.close();
            boolean x = fileToEncrypt.delete();
            encryptedFileOS.close();
            boolean y = encryptedFile.renameTo(new File(fileToEncryptPath));
        } catch (InvalidKeyException ex) {
            Logger.getLogger(AESFileEncryption.class.getName()).log(Level.SEVERE, null, ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(AESFileEncryption.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(AESFileEncryption.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void decrypt(String fileToDecryptPath) {
        try {
            File fileToDecrypt = new File(fileToDecryptPath);
            File decryptedFile = new File("decrypted");
            
            AESCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(AESKey, "AES"));
            
            CipherInputStream fileToDecryptIS = new CipherInputStream(new FileInputStream(fileToDecrypt), AESCipher);
            FileOutputStream decryptedFileOS = new FileOutputStream(decryptedFile);
            byte[] inputBuffer = new byte[1024];
            int len;
            while ((len = fileToDecryptIS.read(inputBuffer)) != -1) {
                decryptedFileOS.write(inputBuffer, 0, len);
            }
            
            fileToDecryptIS.close();
            fileToDecrypt.delete();
            decryptedFileOS.close();
            decryptedFile.renameTo(new File(fileToDecryptPath));
            
        } catch (InvalidKeyException ex) {
            Logger.getLogger(AESFileEncryption.class.getName()).log(Level.SEVERE, null, ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(AESFileEncryption.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(AESFileEncryption.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public InputStream getDecryptedInputStream(String encryptedFilePath) {
        try {
            File encryptedFile = new File(encryptedFilePath);
            
            AESCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(AESKey, "AES"));
            CipherInputStream DecryptedIS = new CipherInputStream(new FileInputStream(encryptedFile), AESCipher);
            int length = (int) encryptedFile.length();
            byte[] inputBuffer = new byte[length];
            int i;
            int len = 0;
            while ((i = DecryptedIS.read(inputBuffer, len, length)) != -1) {
                len += i;
            }
            DecryptedIS.close();
            return new ByteArrayInputStream(inputBuffer);
            
        } catch (InvalidKeyException ex) {
            Logger.getLogger(AESFileEncryption.class.getName()).log(Level.SEVERE, null, ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(AESFileEncryption.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(AESFileEncryption.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
}
