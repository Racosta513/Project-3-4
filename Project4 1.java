import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;

/**
 * Project4 - AES encryption and decryption in ECB and CBC modes.
 * Provides a simple interface for encrypting and decrypting strings using AES.
 */
public class Project4 {

    private static final String AES_ALGORITHM = "AES";
    private static final String AES_ECB = "AES/ECB/PKCS5Padding";
    private static final String AES_CBC = "AES/CBC/PKCS5Padding";

    private static final boolean DEBUG = true; // Enable or disable debug output

    /**
     * Encrypts the given plaintext using AES with the specified key and mode.
     *
     * @param plaintext The input string to encrypt
     * @param key       The key string used for encryption (will be trimmed/padded to 16 bytes)
     * @param useCBC    If true, uses CBC mode; otherwise, uses ECB mode
     * @return Base64-encoded ciphertext
     */
    public static String encrypt(String plaintext, String key, boolean useCBC) throws Exception {
        Cipher cipher;
        SecretKeySpec secretKey = new SecretKeySpec(padKey(key), AES_ALGORITHM);

        if (useCBC) {
            cipher = Cipher.getInstance(AES_CBC);
            IvParameterSpec iv = new IvParameterSpec(new byte[16]); // 16-byte zero IV
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        } else {
            cipher = Cipher.getInstance(AES_ECB);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        }

        byte[] encrypted = cipher.doFinal(plaintext.getBytes());

        if (DEBUG) {
            System.out.println("== ENCRYPT DEBUG ==");
            System.out.println("Mode: " + (useCBC ? "CBC" : "ECB"));
            System.out.println("Plaintext: " + plaintext);
            System.out.println("Key: " + key);
            System.out.println("Cipher (Base64): " + Base64.getEncoder().encodeToString(encrypted));
        }

        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * Decrypts the given ciphertext using AES with the specified key and mode.
     *
     * @param ciphertext The Base64-encoded encrypted string
     * @param key        The key string used for decryption
     * @param useCBC     If true, uses CBC mode; otherwise, uses ECB mode
     * @return The decrypted plaintext string
     */
    public static String decrypt(String ciphertext, String key, boolean useCBC) throws Exception {
        Cipher cipher;
        SecretKeySpec secretKey = new SecretKeySpec(padKey(key), AES_ALGORITHM);
        byte[] cipherBytes = Base64.getDecoder().decode(ciphertext);

        if (useCBC) {
            cipher = Cipher.getInstance(AES_CBC);
            IvParameterSpec iv = new IvParameterSpec(new byte[16]); // Same zero IV as encryption
            cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        } else {
            cipher = Cipher.getInstance(AES_ECB);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
        }

        byte[] decrypted = cipher.doFinal(cipherBytes);

        if (DEBUG) {
            System.out.println("== DECRYPT DEBUG ==");
            System.out.println("Mode: " + (useCBC ? "CBC" : "ECB"));
            System.out.println("Ciphertext (Base64): " + ciphertext);
            System.out.println("Key: " + key);
            System.out.println("Plaintext: " + new String(decrypted));
        }

        return new String(decrypted);
    }

    /**
     * Pads or trims the key string to 16 bytes 
     *
     * @param key The input key string
     * @return A 16-byte array suitable for AES
     */
    private static byte[] padKey(String key) {
        byte[] keyBytes = new byte[16];
        byte[] inputBytes = key.getBytes();
        int len = Math.min(inputBytes.length, 16);
        System.arraycopy(inputBytes, 0, keyBytes, 0, len);
        return keyBytes;
    }

    /**
     * Example usage of the encrypt and decrypt methods.
     */
    public static void main(String[] args) throws Exception {
        String plaintext = "Harry Potter is the Chosen One!";
        String key = "Hogwarts123";
        boolean useCBC = true; // true for CBC, false for ECB

        String encrypted = encrypt(plaintext, key, useCBC);
        String decrypted = decrypt(encrypted, key, useCBC);

        System.out.println("\n== FINAL OUTPUT ==");
        System.out.println("Encrypted: " + encrypted);
        System.out.println("Decrypted: " + decrypted);
    }
}
