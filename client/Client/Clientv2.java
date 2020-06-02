package Client;

import java.net.*;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.DataInputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.io.*;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.print.attribute.standard.Media;

public class Clientv2 {
    // initialize socket and scanner
    private Socket socket;
    private Scanner scanner;

    // constructor to put ip address and port
    private Clientv2(InetAddress ipAddress, int port) throws Exception {
        this.socket = new Socket(ipAddress, port);
        this.scanner = new Scanner(System.in);
    }

    // After successfuly finding ip and port start connection
    private void start(Clientv2 client) throws IOException, InvalidKeyException, NoSuchAlgorithmException,
            InvalidKeySpecException, IllegalStateException, InvalidAlgorithmParameterException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException
    {
        // Receive pubkey DH
        byte[] pubKeyDHServer = receiveServerPubKeyDH(client);
        System.out.println("From Server: " + Utilities.toHexString(pubKeyDHServer));
        // 3. Gera par de chaves Diffie Helman
        byte[] pubKeyClient = DH_Client.getClientPubKeyEnc(pubKeyDHServer);
        // 4. Envia a chave Pub para o Server
        System.out.println("Chave enviada para o server: " + Utilities.toHexString(pubKeyClient));
        sendPubDHToServer(client, pubKeyClient);

        // 6. Gerar chave secreta partilhada
        byte[] clientSecretSharedKey = DH_Client.getClientSharedSecret(pubKeyDHServer);
        System.out.println("Chave Secreta Partilhada: " + Utilities.toHexString(clientSecretSharedKey));

        SecretKeySpec clientAesKey = new SecretKeySpec(clientSecretSharedKey, 0, 16, "AES");
        String message = "Hello world";
        EncryptParams encParam = Utilities.encryptMessage(clientAesKey, message);
        //System.out.println(encParam.ciphertext);
        //System.out.println(encParam.encodedParams);
        
        // Send ciphertext
        sendPubDHToServer(client, encParam.ciphertext);
        // Send encParams
        sendPubDHToServer(client, encParam.encodedParams);

        System.out.println("Mensagem: " + message);

        /*
        //Send pk to Server.
        PublicKey pk = getPubKey();
        sendPubKeyToServer(client, pk);
        //Receive pk to Server.
        receiveServerPubKey(client);

        //Send msg to server and receive feedback.
        sendMSGtoServer(client, this.scanner);
        */
    }

    private static byte[] receiveServerPubKeyDH(Clientv2 client) throws IOException {
        try {
            DataInputStream dIn = new DataInputStream(client.socket.getInputStream());

            int length = dIn.readInt();   
            byte[] message = new byte[length];                 // read length of incoming message
            if(length>0) {
                dIn.readFully(message, 0, message.length); // read the message~                
            }
            return message;
        } catch (Exception e) {
            System.out.println("Caught exception: " + e.toString());
            return null;
        }
    }

    private static void sendPubDHToServer(Clientv2 client, byte[] pk) {
        try {
            DataOutputStream dOut = new DataOutputStream(client.socket.getOutputStream());
            
            System.out.println("SERVER: Enviando chave publica DH para cliente.........");
            dOut.writeInt(pk.length); // write length of the message
            dOut.write(pk);           // write the message
            dOut.flush();
            System.out.println("DONE!");
        } catch (Exception e) {
            System.out.println("Caught exception: " + e.toString());
        }
    }

    private static void sendMSGtoServer (Clientv2 client, Scanner sc) throws IOException {
        String input = sc.nextLine();
        
        try {
            PrintStream toServer = new PrintStream(client.socket.getOutputStream());        

            while (!input.equals("exit") && !input.equals("kys")) 
            {
                System.out.println("Entrei aqui client");
                
                toServer.println(input);
                System.out.println("Message to server: " + input);
                if (!input.equals("exit") && !input.equals("kys")) {
                    feedbackFromServer(client);
                }

                input = sc.nextLine();            
            }

            //System.out.println("..........Closing Connection..........");
            //sc.close();
        } catch (IOException i) 
        {
            System.out.println(i);
        }
        sc.close();
    }

    private static void feedbackFromServer (Clientv2 client) throws IOException {
        BufferedReader in = new BufferedReader(new InputStreamReader(client.socket.getInputStream()));
        String data = null;
         
        try { 
            if((data = in.readLine()) != null)
            {
                System.out.println("Entrei aqui! Cacete");
                System.out.println(data);
            }
        } catch (IOException i) {
            System.out.println("Caught Exception: " + i.toString());
        }
    }

    /**
     * @return public key
     **/
    private static PublicKey getPubKey() 
    {
        try 
        {
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
        } 
        catch (Exception e) 
        {
            System.out.println("Caught exception: " + e.toString());
            return null;
        }
    }

    /**
     * Receives the pub key to the Server
     * 
     * @param client
     * @return
     * @throws IOException
     **/

    private static String receiveServerPubKey(Clientv2 client) throws IOException {
        try {
            BufferedReader inPK = new BufferedReader(new InputStreamReader(client.socket.getInputStream()));
            String receivedPK = inPK.readLine();
            System.out.println("\r\nServer Public Key:\n" + receivedPK);
            return receivedPK;
        } catch (Exception e) {
            System.out.println("Caught exception: " + e.toString());
            return null;
        }
    }

    /**
     * Sends the pub key to the Server
     * @param client
     * @param pk
     * @throws IOException
     **/

    private static void sendPubKeyToServer(Clientv2 client, PublicKey pk) throws IOException 
    {
        try 
        {
            PrintWriter out = new PrintWriter(client.socket.getOutputStream(), false);

            // Send pk to Server
            byte[] key = pk.getEncoded();
            String pk_client = new String(key); //adicionada  
            System.out.println("CLIENTE: Enviando chave publica para servidor.........");
            out.println("-pk " + pk_client);
            out.flush();
        } 
        catch (Exception e)
        {
            System.out.println("Caught exception: " + e.toString());
        }

    }

    public static void main(String[] args) throws Exception 
    {
        Clientv2 client = new Clientv2(InetAddress.getByName(args[0]), Integer.parseInt(args[1]));
        //Check and/or create file with public key
        File f = new File("pub_key");
        if (!f.isFile()) 
        {
            GenKeyPairs genKeys = new GenKeyPairs();
            genKeys.genKeyPairs();
			System.out.println("Par criado");
        }

        //Ligar ao Servidor
        System.out.println("\r\nConnected to Server: " + client.socket.getInetAddress());
        client.start(client);
    }
}