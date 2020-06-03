import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;

public class insertUsersDb {

    public static byte[] genKeyPairs() {

        /* Generate Public and Private Keys */
        byte[] pubkey = null;
        try {
            // Create a Key Pair Generator
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");

            // Initialize the Key Pair Generator
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
            keyGen.initialize(1024, random);

            // Generate the Pair of Keys
            KeyPair pair = keyGen.generateKeyPair();
            // PrivateKey priv = pair.getPrivate();
            PublicKey pub = pair.getPublic();

            // Save the Public Key in a file
            pubkey = pub.getEncoded();
        } catch (Exception e) {
            System.out.println("Caught exception: " + e.toString());
        }
        return pubkey;
    }

    public static void main(String[] args)
            throws NoSuchAlgorithmException, UnsupportedEncodingException, NoSuchProviderException {

        DBUtilities db = new DBUtilities();

        // User 1
        String user1 = "spider";
        byte[] pk1 = genKeyPairs();
        String pk_user1 = Utilities.getPublicKey(pk1).toString();
        String pw_user1 = "man";
        //System.out.println("User: " + user1 + " / PK: " + pk_user1 + " / Pw: " + pw_user1);
        db.insertUser(user1, pk_user1, pw_user1.getBytes("UTF-8"));

        // User 2
        String user2 = "xmen";
        byte[] pk2 = genKeyPairs();
        String pk_user2 = Utilities.getPublicKey(pk2).toString();
        String pw_user2 = "xavier";
        //System.out.println("User: " + user2 + " / PK: " + pk_user2 + " / Pw: " + pw_user2);
        db.insertUser(user2, pk_user2, pw_user2.getBytes("UTF-8"));

        // User 3
        String user3 = "robot";
        byte[] pk3 = genKeyPairs();
        String pk_user3 = Utilities.getPublicKey(pk3).toString();
        String pw_user3 = "cop";
        //System.out.println("User: " + user3 + " / PK: " + pk_user3 + " / Pw: " + pw_user3);
        db.insertUser(user3, pk_user3, pw_user3.getBytes("UTF-8"));
        
    }
    
}