
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class Utilities {

    public Utilities() {
    }

    public static EncryptParams encryptMessage(SecretKeySpec aesKey, byte[] message) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        /*
         * Encrypts, using AES in CBC mode
         */

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] cleartext = message;
        byte[] ciphertext = cipher.doFinal(cleartext);

        // Retrieve the parameter that was used
        byte[] encodedParams = cipher.getParameters().getEncoded();

        return new EncryptParams(ciphertext, encodedParams);
    }

    public static byte[] decryptMode(SecretKeySpec aesKey, byte[] encodedParams, byte[] ciphertext)
            throws NoSuchAlgorithmException, IOException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        /*
         * Decrypts, using AES in CBC mode
         */

        // Instantiate AlgorithmParameters object from parameter encoding
        AlgorithmParameters aesParams = AlgorithmParameters.getInstance("AES");
        aesParams.init(encodedParams);
        Cipher aliceCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aliceCipher.init(Cipher.DECRYPT_MODE, aesKey, aesParams);
        byte[] recovered = aliceCipher.doFinal(ciphertext);

        return recovered;
    }

    /*
     * Converts a byte to hex digit and writes to the supplied buffer
     */
    public static void byte2hex(byte b, StringBuffer buf) {
        char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        int high = ((b & 0xf0) >> 4);
        int low = (b & 0x0f);
        buf.append(hexChars[high]);
        buf.append(hexChars[low]);
    }

    /*
     * Converts a byte array to hex string
     */
    public static String toHexString(byte[] block) {
        StringBuffer buf = new StringBuffer();
        int len = block.length;
        for (int i = 0; i < len; i++) {
            byte2hex(block[i], buf);
            // if (i < len - 1) {
            // buf.append(":");
            // }
        }
        return buf.toString();
    }

    /*
     * Converts a hex string to ascii string
     */
    public static String hexToAscii(String hexStr) {
        StringBuilder output = new StringBuilder("");

        for (int i = 0; i < hexStr.length(); i += 2) {
            String str = hexStr.substring(i, i + 2);
            output.append((char) Integer.parseInt(str, 16));
        }

        return output.toString();
    }

    /*
     * Calculate HMAC SHA 256
     */
    public static byte[] HmacSha256(byte[] secretKey, byte[] message) {
        byte[] hmacSha256 = null;

        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, "HmacSHA256");
            mac.init(secretKeySpec);
            hmacSha256 = mac.doFinal(message);
        } catch (Exception e) {
            throw new RuntimeException("Failed to calculate hmac-sha256", e);
        }

        return hmacSha256;
    }

    /**
     * Returns Public Key DSA/SUN
     * 
     * @param base64PublicKey
     * @return
     * @throws NoSuchProviderException
     */
    public static PublicKey getPublicKey(byte[] pubKey) throws NoSuchProviderException {
        PublicKey publicKey = null;
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pubKey);
            KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");
            publicKey = keyFactory.generatePublic(keySpec);
            return publicKey;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    /**
     * Sign a message with a private key
     * 
     * @param message
     * @param sk
     * @return
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws UnsupportedEncodingException
     */
    public static byte[] sign(String message, PrivateKey sk) throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidKeyException, SignatureException, UnsupportedEncodingException {
        // Get a Signature Object
        Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");
        // Initialize the Signature Object
        dsa.initSign(sk);
        // Supply the Signature Object the Data to be Signed
        dsa.update(message.getBytes("UTF8"));
        // Generate the Signature
        byte[] realSig = dsa.sign();

        return realSig;
    }

    /**
     * Verify a digital signature
     * 
     * @param pk
     * @param signature
     * @param message
     * @return
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws UnsupportedEncodingException
     * @throws SignatureException
     */
    public static boolean verifySignature(PublicKey pk, byte[] signature, byte[] message)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException,
            UnsupportedEncodingException {
        // Initialize the Signature Object for Verification
        Signature sig = Signature.getInstance("SHA1withDSA", "SUN");
        // Initialize the Signature Object
        sig.initVerify(pk);
        // Supply the Signature Object the Data to be Signed
        sig.update(message);
        /* Verify the Signature */
        boolean verifies = sig.verify(signature);

        return verifies;
    }

    public static byte[] nonce() throws NoSuchAlgorithmException {
        SecureRandom oSR = SecureRandom.getInstance("SHA1PRNG"); 
        BigInteger oBIdesafio = new BigInteger(oSR.generateSeed(128));

        return oBIdesafio.toByteArray();
    }
}