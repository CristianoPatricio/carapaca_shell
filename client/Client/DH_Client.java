package Client;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

public class DH_Client {

    public DH_Client () {}

    private static KeyAgreement clientKeyAgree;
    
    public static byte[] getClientPubKeyEnc(byte[] serverPubKeyEnc) 
        throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException,
            InvalidKeyException {
        /*
         * Client has received Server's public key in encoded format.
         * He instantiates a DH public key from the encoded key material.
         */
        KeyFactory clientKeyFac = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(serverPubKeyEnc);

        PublicKey serverPubKey = clientKeyFac.generatePublic(x509KeySpec);

        /*
         * Client gets the DH parameters associated with Server's public key.
         * He must use the same parameters when he generates his own key pair.
         */
        DHParameterSpec dhParamFromServerPubKey = ((DHPublicKey)serverPubKey).getParams();

        // Client creates his own DH key pair
        KeyPairGenerator clientKpairGen = KeyPairGenerator.getInstance("DH");
        clientKpairGen.initialize(dhParamFromServerPubKey);
        KeyPair clientKpair = clientKpairGen.generateKeyPair();

        // Client creates and initializes his DH KeyAgreement object
        clientKeyAgree = KeyAgreement.getInstance("DH");
        clientKeyAgree.init(clientKpair.getPrivate());

        // Client encodes his public key, and sends it over to Server.
        byte[] clientPubKeyEnc = clientKpair.getPublic().getEncoded();
        
        return clientPubKeyEnc;
    }

    public static byte[] getClientSharedSecret(byte[] serverPubKeyEnc)
            throws NoSuchAlgorithmException, InvalidKeySpecException,
            InvalidKeyException, IllegalStateException {

        /*
         * Client uses Server's public key for the first (and only) phase of his version of the DH protocol.
         */
        KeyFactory clientKeyFac = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(serverPubKeyEnc);
        PublicKey serverPubKey = clientKeyFac.generatePublic(x509KeySpec);
        clientKeyAgree.doPhase(serverPubKey, true);
        byte[] clientSharedSecret = clientKeyAgree.generateSecret();

        return clientSharedSecret;
    }
}