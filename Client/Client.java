import java.net.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.io.*;
import java.util.Scanner;

class DSAKeyPair {

    PrivateKey priv;
    PublicKey pub;

    DSAKeyPair(PrivateKey sk, PublicKey pk) {
        priv = sk;
        pub = pk;
    }
}

public class Client 
{
    // initialize socket and scanner
    private Socket socket;
    private Scanner scanner;

    // constructor to put ip address and port
    private Client(InetAddress ipAddress, int port) throws Exception
    {
        this.socket = new Socket(ipAddress,port);
        this.scanner = new Scanner(System.in);
    }

    private void start() throws IOException
    {
        String input = "";

        PrintWriter out = new PrintWriter(this.socket.getOutputStream(), true);
        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

        // Get Private and Public Key
        DSAKeyPair pubKey = getKeyPair();
        PublicKey pk = pubKey.pub;
        
        // Send pk to Server
        sendPubKeyToServer(pk, out);
        
        while (!input.equals("exit")) {
            input = scanner.nextLine();
            out.println(input);
            out.flush();

            String messageFromServer = in.readLine();
            whileChatting(messageFromServer);
        }

        // close the connection
        try {
            socket.close();
        } catch (IOException i) {
            System.out.println(i);
        }
    }

    private void whileChatting(String messageFromServer) {
        System.out.println("\r\nMessage from Server to Client: " + messageFromServer);
    }

    private DSAKeyPair getKeyPair() {

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

            return new DSAKeyPair(priv, pub);

        } catch (Exception e) {
            System.out.println("Caught exception: " + e.toString());
            return null;
        }
    }

    private void sendPubKeyToServer(PublicKey pub, PrintWriter out) {
        // Send pk to Server
        byte[] key = pub.getEncoded();
        out.println(key);
    }

    public static void main(String[] args) throws Exception 
    {
        Client client = new Client(InetAddress.getByName(args[0]), Integer.parseInt(args[1]));

        System.out.println("\r\nConnected to Server: " + client.socket.getInetAddress());
        client.start();
    }
}