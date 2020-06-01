import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

public class DH_Server {

    public DH_Server() {
    }

    private static KeyAgreement serverKeyAgree;

    public static byte[] getServerPubKeyEnc() throws Exception {

        /* Server creates her own DH key pair with 2048-bit key size */
        KeyPairGenerator serverKpairGen = KeyPairGenerator.getInstance("DH");
        serverKpairGen.initialize(2048);
        KeyPair serverKpair = serverKpairGen.generateKeyPair();

        // Server creates and initializes her DH KeyAgreement object
        serverKeyAgree = KeyAgreement.getInstance("DH");
        serverKeyAgree.init(serverKpair.getPrivate());

        // Server encodes her public key, and sends it over to Client.
        byte[] serverPubKeyEnc = serverKpair.getPublic().getEncoded();

        return serverPubKeyEnc;
    }

    public static byte[] getServerSharedSecretKey(byte[] clientPubKeyEnc) throws NoSuchAlgorithmException,
            InvalidKeySpecException, InvalidKeyException, IllegalStateException {

        /*
         * Server uses Client's public key for the first (and only) phase of her version
         * of the DH protocol. Before she can do so, she has to instantiate a DH public
         * key from Client's encoded key material.
         */
        KeyFactory serverKeyFac = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(clientPubKeyEnc);
        PublicKey clientPubKey = serverKeyFac.generatePublic(x509KeySpec);
        serverKeyAgree.doPhase(clientPubKey, true);
        byte[] serverSharedSecret = serverKeyAgree.generateSecret();

        return serverSharedSecret;
    }

    /*
    System.out.println("Use shared secret as SecretKey object ...");

    SecretKeySpec bobAesKey = new SecretKeySpec(bobSharedSecret, 0, 16, "AES");
    SecretKeySpec aliceAesKey = new SecretKeySpec(aliceSharedSecret, 0, 16, "AES");*/

    

    /*
     * Alice decrypts, using AES in CBC mode
     */

    // Instantiate AlgorithmParameters object from parameter encoding
    // obtained from Bob
    /*
    AlgorithmParameters aesParams = AlgorithmParameters.getInstance("AES");aesParams.init(encodedParams);
    Cipher aliceCipher = Cipher
            .getInstance("AES/CBC/PKCS5Padding");aliceCipher.init(Cipher.DECRYPT_MODE,aliceAesKey,aesParams);
    byte[] recovered = aliceCipher.doFinal(ciphertext);if(!java.util.Arrays.equals(cleartext,recovered))throw new Exception("AES in CBC mode recovered text is "+"different from cleartext");System.out.println("AES in CBC mode recovered text is "+"same as cleartext");*/
}