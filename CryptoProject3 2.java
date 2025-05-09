import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * CryptoProject3 is a cryptographic library that implements
 * Diffie-Hellman Key Exchange and RSA Encryption/Decryption with Digital Signatures.
 * 
 * Project 3 Implementation.
 */
public class CryptoProject3 {

    private static final SecureRandom random = new SecureRandom();

    //Diffie-Hellman

    /**
     * Generates a private key for Diffie-Hellman key exchange.
     * 
     * @param bitLength The bit length of the key.
     * @return A randomly generated private key.
     */
    public static BigInteger generatePrivateKey(int bitLength) {
        return new BigInteger(bitLength, random);
    }

    /**
     * Generates the public key for Diffie-Hellman key exchange.
     * 
     * @param g The generator.
     * @param p The prime modulus.
     * @param privateKey The private key.
     * @return The computed public key.
     */
    public static BigInteger generatePublicKey(BigInteger g, BigInteger p, BigInteger privateKey) {
        return fastMod(g, privateKey, p);
    }

    /**
     * Computes the shared secret using the other party's public key and own private key.
     * 
     * @param publicKey The other party's public key.
     * @param privateKey Your private key.
     * @param p The prime modulus.
     * @return The computed shared secret.
     */
    public static BigInteger computeSharedSecret(BigInteger publicKey, BigInteger privateKey, BigInteger p) {
        return fastMod(publicKey, privateKey, p);
    }

    //RSA

    /**
     * Generates RSA public and private keys.
     * 
     * @param bitLength The desired bit length of the modulus n.
     * @return An array containing {public exponent e, private exponent d, modulus n}.
     */
    public static BigInteger[] generateRSAKeys(int bitLength) {
        BigInteger p = BigInteger.probablePrime(bitLength / 2, random);
        BigInteger q = BigInteger.probablePrime(bitLength / 2, random);
        BigInteger n = p.multiply(q);
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        BigInteger e = BigInteger.valueOf(65537); // Common choice for e
        if (!phi.gcd(e).equals(BigInteger.ONE)) {
            e = BigInteger.probablePrime(bitLength / 2, random);
        }

        BigInteger d = e.modInverse(phi);
        return new BigInteger[]{e, d, n};
    }

    /**
     * Encrypts a message using RSA.
     * 
     * @param message The plaintext message as a BigInteger.
     * @param e The public exponent.
     * @param n The modulus.
     * @return The encrypted ciphertext.
     */
    public static BigInteger rsaEncrypt(BigInteger message, BigInteger e, BigInteger n) {
        return fastMod(message, e, n);
    }

    /**
     * Decrypts a ciphertext using RSA.
     * 
     * @param ciphertext The ciphertext as a BigInteger.
     * @param d The private exponent.
     * @param n The modulus.
     * @return The decrypted plaintext message.
     */
    public static BigInteger rsaDecrypt(BigInteger ciphertext, BigInteger d, BigInteger n) {
        return fastMod(ciphertext, d, n);
    }

    /**
     * Generates a digital signature using RSA.
     * 
     * @param message The message to sign.
     * @param d The private exponent.
     * @param n The modulus.
     * @return The digital signature.
     */
    public static BigInteger rsaSign(BigInteger message, BigInteger d, BigInteger n) {
        return fastMod(message, d, n);
    }

    /**
     * Verifies a digital signature using RSA.
     * 
     * @param message The original message.
     * @param signature The signature to verify.
     * @param e The public exponent.
     * @param n The modulus.
     * @return True if the signature is valid, false otherwise.
     */
    public static boolean rsaVerify(BigInteger message, BigInteger signature, BigInteger e, BigInteger n) {
        return fastMod(signature, e, n).equals(message);
    }

    //Utilities

    /**
     * Performs fast modular exponentiation (base^exp mod mod).
     * 
     * @param base The base.
     * @param exp The exponent.
     * @param mod The modulus.
     * @return The result of (base^exp) mod mod.
     */
    public static BigInteger fastMod(BigInteger base, BigInteger exp, BigInteger mod) {
        BigInteger result = BigInteger.ONE;
        base = base.mod(mod);

        while (exp.compareTo(BigInteger.ZERO) > 0) {
            if (exp.testBit(0)) {
                result = result.multiply(base).mod(mod);
            }
            base = base.multiply(base).mod(mod);
            exp = exp.shiftRight(1);
        }
        return result;
    }

    //Demo Main

    /**
     * Demonstrates Diffie-Hellman Key Exchange and RSA Encryption/Decryption with Digital Signatures.
     * 
     * @param args Command-line arguments (not used).
     */
    public static void main(String[] args) {
        // ----- Diffie-Hellman Demo -----
        System.out.println("---- Diffie-Hellman Key Exchange ----");
        int dhBitLength = 512;
        BigInteger p = BigInteger.probablePrime(dhBitLength, random);
        BigInteger g = BigInteger.valueOf(2); // Simple generator

        BigInteger alicePrivate = generatePrivateKey(dhBitLength);
        BigInteger bobPrivate = generatePrivateKey(dhBitLength);

        BigInteger alicePublic = generatePublicKey(g, p, alicePrivate);
        BigInteger bobPublic = generatePublicKey(g, p, bobPrivate);

        BigInteger aliceShared = computeSharedSecret(bobPublic, alicePrivate, p);
        BigInteger bobShared = computeSharedSecret(alicePublic, bobPrivate, p);

        System.out.println("Shared Secret (Alice): " + aliceShared);
        System.out.println("Shared Secret (Bob): " + bobShared);
        System.out.println("Keys Match: " + aliceShared.equals(bobShared));

        // ----- RSA Demo -----
        System.out.println("\n---- RSA Encryption/Decryption ----");
        int rsaBitLength = 1024;
        BigInteger[] rsaKeys = generateRSAKeys(rsaBitLength);
        BigInteger e = rsaKeys[0];
        BigInteger d = rsaKeys[1];
        BigInteger n = rsaKeys[2];

        BigInteger message = new BigInteger("123456789");
        BigInteger ciphertext = rsaEncrypt(message, e, n);
        BigInteger decrypted = rsaDecrypt(ciphertext, d, n);

        System.out.println("Original Message: " + message);
        System.out.println("Encrypted Message: " + ciphertext);
        System.out.println("Decrypted Message: " + decrypted);

        // ----- RSA Digital Signature -----
        System.out.println("\n---- RSA Digital Signature ----");
        BigInteger signature = rsaSign(message, d, n);
        boolean isVerified = rsaVerify(message, signature, e, n);

        System.out.println("Signature: " + signature);
        System.out.println("Signature Verified: " + isVerified);
    }
}
