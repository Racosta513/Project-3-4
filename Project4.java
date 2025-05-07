import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;

public class Project4 {

    private static final String AES_ALGORITHM = "AES";
    private static final String AES_ECB = "AES/ECB/PKCS5Padding";
    private static final String AES_CBC = "AES/CBC/PKCS5Padding";

    private static final boolean DEBUG = true;

    // Encrypt method
    public static String encrypt(String plaintext, String key, boolean useCBC) throws Exception {
        Cipher cipher;
        SecretKeySpec secretKey = new SecretKeySpec(padKey(key), AES_ALGORITHM);

        if (useCBC) {
            cipher = Cipher.getInstance(AES_CBC);
            IvParameterSpec iv = new IvParameterSpec(new byte[16]); // Zero IV for simplicity
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

    // Decrypt method
    public static String decrypt(String ciphertext, String key, boolean useCBC) throws Exception {
        Cipher cipher;
        SecretKeySpec secretKey = new SecretKeySpec(padKey(key), AES_ALGORITHM);
        byte[] cipherBytes = Base64.getDecoder().decode(ciphertext);

        if (useCBC) {
            cipher = Cipher.getInstance(AES_CBC);
            IvParameterSpec iv = new IvParameterSpec(new byte[16]); // Same zero IV
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

    // Pad or trim key to 16 bytes (128 bits)
    private static byte[] padKey(String key) {
        byte[] keyBytes = new byte[16];
        byte[] inputBytes = key.getBytes();
        int len = Math.min(inputBytes.length, 16);
        System.arraycopy(inputBytes, 0, keyBytes, 0, len);
        return keyBytes;
    }

    // Example main method
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
