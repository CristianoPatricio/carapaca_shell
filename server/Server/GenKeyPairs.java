
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

public class GenKeyPairs {

    public void genKeyPairs() {

        /* Generate Public and Private Keys */

        try {
            // Create a Key Pair Generator
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");

            // Initialize the Key Pair Generator
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
            keyGen.initialize(1024, random);

            // Generate the Pair of Keys
            KeyPair pair = keyGen.generateKeyPair();
            PrivateKey priv = pair.getPrivate();
            PublicKey pub = pair.getPublic();

            // Save the Public Key in a file
            byte[] pubkey = pub.getEncoded();
            FileOutputStream keyfos = new FileOutputStream("pub_key");
            keyfos.write(pubkey);
            keyfos.close();

            // Save the Private Key in a file
            byte[] privkey = priv.getEncoded();
            keyfos = new FileOutputStream("priv_key");
            keyfos.write(privkey);
            keyfos.close();

        } catch (Exception e) {
            System.out.println("Caught exception: " + e.toString());          
        }
    }
}