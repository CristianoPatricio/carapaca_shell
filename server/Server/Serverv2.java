package Server;

import java.io.*;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.math.BigInteger;
import java.util.Scanner;
import javax.crypto.spec.SecretKeySpec;
import java.io.PrintWriter;
import java.security.SecureRandom;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.io.File;
import java.io.FileWriter;
import java.io.FileReader;
import java.io.IOException;
import java.security.spec.X509EncodedKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;

public class Serverv2 {

    private ServerSocket server;

    public Serverv2(String ipAddress) throws Exception {
        // 0 -> port number that is automatically allocated
        // 1 -> requested maximum length of the queue of incoming connections
        this.server = new ServerSocket(50172, 1, InetAddress.getByName(ipAddress));
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

    private void listen() throws Exception 
    {
        Socket client = this.server.accept();
        String clientAddress = client.getInetAddress().getHostAddress();
        System.out.println("\r\nNew connection from " + clientAddress);

        // 1. Gera par de chaves Diffie Helman
        byte[] pubKeyServer = DH_Server.getServerPubKeyEnc();
        System.out.println("Chave enviada para o cliente: " + Utilities.toHexString(pubKeyServer));
        // 2. Enviar a pubkey para o cliente
        sendPubDHToClient(client, pubKeyServer);
        // 5. Receive pubKeyDH client
        byte[] receiveClientPubKeyDH = receiveClientPubKeyDH(client);
        System.out.println("From Client: " + Utilities.toHexString(receiveClientPubKeyDH));

        // 7. Gerar chave secreta partilhada
        byte[] serverSecretSharedKey = DH_Server.getServerSharedSecretKey(receiveClientPubKeyDH);
        System.out.println("Chave Secreta Partilhada: " + Utilities.toHexString(serverSecretSharedKey));

        SecretKeySpec serverAesKey = new SecretKeySpec(serverSecretSharedKey, 0, 16, "AES");

        // 5. Receive pubKeyDH client
        byte[] ciphertext = receiveClientPubKeyDH(client);
        // 5. Receive pubKeyDH client
        byte[] encodedParams = receiveClientPubKeyDH(client);

        byte[] messageDecrypt = Utilities.decryptMode(serverAesKey, encodedParams, ciphertext);
        System.out.println("Mensagem: " + Utilities.hexToAscii(Utilities.toHexString(messageDecrypt)));

        /*
        //get client public Key
        BufferedReader inPK = new BufferedReader(new InputStreamReader(client.getInputStream()));
        String receivedPK = inPK.readLine();
        System.out.println("\r\nClient Public Key:\n" + receivedPK);

        //Send Server public key to client:
        PublicKey pk = getPubKey();
        sendPubKeyToclient(client, pk);

        receiveClientMSG(client, clientAddress);
        */
    }

    /**
     * Receives the pub key to the Server
     * 
     * @param client
     * @return
     * @throws IOException
     **/

    private static byte[] receiveClientPubKeyDH(Socket client) throws IOException {
        try {
            DataInputStream dIn = new DataInputStream(client.getInputStream());
            
            int length = dIn.readInt();
            byte[] message = new byte[length];                    // read length of incoming message
            if(length>0) {
                dIn.readFully(message, 0, message.length); // read the message~                
            }
            return message;
        } catch (Exception e) {
            System.out.println("Caught exception: " + e.toString());
            return null;
        }
    }

    private static void receiveClientMSG (Socket client, String clientAddress) throws IOException {
        BufferedReader in = new BufferedReader(new InputStreamReader(client.getInputStream()));
        PrintWriter out = new PrintWriter(client.getOutputStream(), true);
        String mensagem = "recebido";

        String data = null;

        try {
            //Todas as verificações foram feitas:
            while ((data = in.readLine()) != null) 
            {
                System.out.println("Entrei aqui server");
                if(data.equals("kys"))
                {
                    end(client);
                }
                else if (data.equals("exit")) 
                {
                    return;    
                }   
                else
                {
                    System.out.println("\r\nMessage from " + clientAddress + ": " + data);
                    out.println(mensagem);
                    out.flush();
                }
            }
        } catch (IOException i) {
            System.out.println("Caught Exception: " + i.toString());
        }
    }


    private static void sendPubDHToClient(Socket client, byte[] pk) {
        try {
            DataOutputStream dOut = new DataOutputStream(client.getOutputStream());
            
            System.out.println("SERVER: Enviando chave publica DH para cliente.........");
            dOut.writeInt(pk.length); // write length of the message
            dOut.write(pk);           // write the message
            dOut.flush();
            System.out.println("DONE!");
        } catch (Exception e) {
            System.out.println("Caught exception: " + e.toString());
        }
    }

    private static void sendPubKeyToclient(Socket client, PublicKey pk) throws IOException 
    {
        try 
        {
            byte[] key = pk.getEncoded();
            String pk_client = new String(key);

            PrintStream toClient = new PrintStream(client.getOutputStream());
            System.out.println("SERVER: Enviando chave publica para cliente.........");
            toClient.println(pk_client);

        } catch (Exception e) {
            System.out.println("Caught exception: " + e.toString());
        }
    }

    /*private static void sendPubKeyToclient(Socket client, PublicKey pk) throws IOException 
    {
        try 
        {
            PrintWriter out = new PrintWriter(client.getOutputStream(), false);

            // Send pk to Client
            byte[] key = pk.getEncoded();
            String pk_client = new String(key); //adicionada  
            System.out.println("SERVER: Enviando chave publica para cliente.........");
            out.println("-pk " + pk_client);
            out.flush();
        }
        catch (Exception e)
        {
            System.out.println("Caught exception: " + e.toString());
        }
    }*/

    public InetAddress getSocketAddress(){
        return this.server.getInetAddress();
    }

    public int getPort(){
        return this.server.getLocalPort();
    }

    public static void end(Socket client)
    {
        System.out.println("..........Closing Server..........");
        try
        {
            client.close();
            System.exit(0);
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }

    }

    public static void main(String[] args) throws Exception 
    {
        //criar chaves.
        File f = new File("pub_key");
        if (!f.isFile()) {
            GenKeyPairs genKeys = new GenKeyPairs();
            genKeys.genKeyPairs();
            System.out.println("Par criado");
        }

        //Criar servidor:
        Serverv2 app = new Serverv2(args[0]);
        System.out.println("\r\nRunning Server: " + "Host=" + app.getSocketAddress().getHostAddress() + " Port=" + app.getPort());
        System.out.println("Waiting...");

        //Começar a ouvir:
        while(true)
        {
            app.listen();
            System.out.println("Previous Connection Closed.");    
            System.out.println("Waiting for more connections...");
        }
    }
}