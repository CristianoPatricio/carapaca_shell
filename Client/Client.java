import java.net.*;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.io.*;
import java.util.Scanner;

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
        
        while (!input.equals("exit")) {
            PrintWriter out = new PrintWriter(this.socket.getOutputStream(), true);
            input = scanner.nextLine();
            out.println(input);
            out.flush();

            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
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

    /**
     * Sends the pub key to the Server
     * @param client
     * @param pk
     * @throws IOException
     */
    private static void sendPubKeyToServer(Client client, PublicKey pk) throws IOException {
        
        try {
            PrintWriter out = new PrintWriter(client.socket.getOutputStream(), true);

            // Send pk to Server
            byte[] key = pk.getEncoded();
            out.println(key);
        } catch (Exception e) {
            System.out.println("Caught exception: " + e.toString());
        }
        
    }

    /**
     * 
     * @return public key
     */
    private static PublicKey getPubKey() {

        try {
            // get pub key and send it to the Server
            FileInputStream keyfis = new FileInputStream("pub_key");
            byte[] encKey = new byte[keyfis.available()];
            keyfis.read(encKey);
            keyfis.close();

            // Obtain a key specification
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);

            // KeyFactory to do the conversion
            KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");

            // Generate a PublicKey from the key specification
            PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

            return pubKey;
        } catch (Exception e) {
            System.out.println("Caught exception: " + e.toString());
            return null;
        }
    }

    public static void main(String[] args) throws Exception {

        Client client = new Client(InetAddress.getByName(args[0]), Integer.parseInt(args[1]));

        // Verify if the file that contains the public key exists
        File f = new File("pub_key");
        if (f.isFile()) {
            // Get Public Key From File
            PublicKey pk = getPubKey();

            // Send pub key to client
            sendPubKeyToServer(client, pk);
        } else {
            // Generate key pair and creates the files
            GenKeyPairs genKeys = new GenKeyPairs();
            genKeys.genKeyPairs();

            // Get Public Key From File
            PublicKey pk = getPubKey();

            // Send pub key to client
            sendPubKeyToServer(client, pk);
        }

        System.out.println("\r\nConnected to Server: " + client.socket.getInetAddress());
        client.start();
    }
}