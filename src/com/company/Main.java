package com.company;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) {
        try {
            AES_ENCRYPTION aes_encryption = new AES_ENCRYPTION();
            Scanner scanner = new Scanner(System.in);

            while(true) {

                System.out.println("Enter your secret key :");
                String secretKey = scanner.nextLine();
                SecretKey key = aes_encryption.init(secretKey);
                System.out.println("Enter your message :");
                String message = scanner.nextLine();
                String encryptedMessage = aes_encryption.encrypt(message, key);
                System.out.println("Encrypted Message :"+ encryptedMessage +"\n");
                System.out.println("Do you need send this message? [Y-Yes , N-No ] :");
                String answer = scanner.nextLine();
                if(answer.equals("Y")){
                    System.out.println("Enter the secret key :");
                    secretKey = scanner.nextLine();
                    key =  aes_encryption.init(secretKey);
                    String decryptMessage = aes_encryption.decrypt(encryptedMessage, key);
                    System.out.println("Decrypted Message :"+ decryptMessage+"\n");
                    System.out.println("Do you need to exit? [Y-Yes, N-No] :");
                    answer = scanner.nextLine();
                    if(answer.equals("Y")){
                        return;
                    }

                }

            }

        } catch (Exception exception) {
            System.out.println("Exception :"+exception.getMessage());
        }
    }
}

class AES_ENCRYPTION  {

    private final int DATA_LENGTH = 128;
    private Cipher encryptionCipher;

    public SecretKey init(String stringKey) throws Exception {
        MessageDigest messageDigest =MessageDigest.getInstance("SHA-1");
        byte[] secretKeyBytes = messageDigest.digest(stringKey.getBytes(StandardCharsets.UTF_8));
        return new SecretKeySpec(Arrays.copyOf(secretKeyBytes, 16), "AES");
    }

    public String encrypt(String data, SecretKey key) throws Exception {
        byte[] dataInBytes = data.getBytes();
        encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        encryptionCipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = encryptionCipher.doFinal(dataInBytes);
        return encode(encryptedBytes);
    }

    public String decrypt(String encryptedData, SecretKey key) throws Exception {
        byte[] dataInBytes = decode(encryptedData);
        Cipher decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(DATA_LENGTH, encryptionCipher.getIV());
        decryptionCipher.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] decryptedBytes = decryptionCipher.doFinal(dataInBytes);
        return new String(decryptedBytes);
    }

    private String encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    private byte[] decode(String data) {
        return Base64.getDecoder().decode(data);
    }

}
