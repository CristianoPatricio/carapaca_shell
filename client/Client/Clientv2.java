import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
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
import java.security.KeyStore.PrivateKeyEntry;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.io.*;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.print.attribute.standard.Media;
import java.io.Console;
import java.util.Arrays;

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
    private void start(Clientv2 client, String username) throws IOException, InvalidKeyException, NoSuchAlgorithmException,
            InvalidKeySpecException, IllegalStateException, InvalidAlgorithmParameterException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException
    {
        // Enviar a public key para o Servidor
        byte[] pk = getPubKey();
        sendBytesToServer(client, pk);

        // Enviar o username para o Servidor
        String user = username;
        sendBytesToServer(client, user.getBytes("UTF-8"));

        // Receive pubkey DH
        byte[] pubKeyDHServer = receiveBytesFromServer(client);
        System.out.println("\r\nPub key received from server: " + Utilities.toHexString(pubKeyDHServer));

        // Gera par de chaves Diffie Helman
        byte[] pubKeyClient = DH_Client.getClientPubKeyEnc(pubKeyDHServer);
        // Envia a chave Pub para o Server.
        System.out.println("\r\nPub key sent to server: " + Utilities.toHexString(pubKeyClient));
        sendBytesToServer(client, pubKeyClient);
        // Gerar chave secreta partilhada
        byte[] clientSecretSharedKey = DH_Client.getClientSharedSecret(pubKeyDHServer);
        System.out.println("\r\nShared secret key: " + Utilities.toHexString(clientSecretSharedKey)); 

        System.out.println("\n\n");

        // Receive Method
        String method = new String(receiveSecureMessageFromServer(client,clientSecretSharedKey), StandardCharsets.UTF_8);
        if (method.equals("pk_auth")) { // Public Key Authentication
            // Receive Nonce
            //byte[] nonce = receiveSecureMessageFromServer(client,clientSecretSharedKey);
            byte[] nonce = receiveBytesFromServer(client);
            String nonceToString = new String(nonce, StandardCharsets.UTF_8);
            //System.out.println("Numero: " + nonceToString);

            // Sign nonce
            byte[] sign = null;
            PrivateKey sk = getPrivKey();
            try {
                sign = Utilities.sign(nonce,sk);
                //System.out.println("Signature: " + Utilities.hexToAscii(Utilities.toHexString(sign)));
            } catch (Exception e) {
                System.out.println(e.toString());
            }
        
            // Send sign to Client
            //sendSecureMessageToServer(client, clientSecretSharedKey,sign);
            sendBytesToServer(client, sign);
        } else { // Password Authentication
            String enterPw = new String(receiveSecureMessageFromServer(client,clientSecretSharedKey), StandardCharsets.UTF_8);
            System.out.print(enterPw+"");
            String password =  this.scanner.nextLine();
            // Enviar a password para o Servidor
            sendSecureMessageToServer(client, clientSecretSharedKey, password.getBytes("UTF-8"));
        }
        
        String confirm = "NOK";

        do {
            // Receive confirmation
            byte[] confirmation = receiveSecureMessageFromServer(client,clientSecretSharedKey);
            confirm = new String(confirmation, StandardCharsets.UTF_8);

            if (confirm.equals("OK")) { // Cliente Autenticado
                sendMSGtoServer(client, this.scanner, clientSecretSharedKey, username);
            } else if (confirm.equals("NOK")) {
                System.out.println("Incorrect Password! Please enter the correct password.");
                String enterPw = new String(receiveSecureMessageFromServer(client,clientSecretSharedKey), StandardCharsets.UTF_8);
                System.out.print(enterPw+"");
                String password =  this.scanner.nextLine();
                // Enviar a password para o Servidor
                sendSecureMessageToServer(client, clientSecretSharedKey,password.getBytes("UTF-8"));
            } else if (confirm.equals("Exit")) {
                System.out.println("..........Closing Connection..........");
                client.socket.close();
                break;
            }
        } while (confirm.equals("NOK"));
    }

    /*public char[] readPassword() {
        return readPassword("");
    }*/

    /**
     * Receive bytes from server
     * @param client
     * @return pubkey
     * @throws IOException
     */
    private static byte[] receiveBytesFromServer(Clientv2 client) throws IOException {
        try {
            DataInputStream dIn = new DataInputStream(client.socket.getInputStream());

            int length = dIn.readInt();   
            byte[] message = new byte[length];      
            if(length > 0) {
                dIn.readFully(message, 0, message.length);             
            }

            return message;
        } catch (Exception e) {
            System.out.println("Caught exception: " + e.toString());
            return null;
        }
    }

    /**
     * Sends public key to Server
     * @param client
     * @param pk
     */
    private static void sendBytesToServer(Clientv2 client, byte[] pk) {
        try {
            DataOutputStream dOut = new DataOutputStream(client.socket.getOutputStream());
            
            //System.out.println("SERVER: Sending public key to server...");
            dOut.writeInt(pk.length); // write length of the message
            dOut.write(pk);           // write the message
            dOut.flush();
            //System.out.println("Sent successfully!");
        } catch (Exception e) {
            System.out.println("Caught exception: " + e.toString());
        }
    }

    private static void sendSecureMessageToServer(Clientv2 client, byte[] clientSecretSharedKey, byte[] message) {

        SecretKeySpec clientAesKey = new SecretKeySpec(clientSecretSharedKey, 0, 16, "AES");

        try {
            DataOutputStream dOut = new DataOutputStream(client.socket.getOutputStream());

            // Calculate HMAC SHA 256
            byte[] hmacSha256 = Utilities.HmacSha256(clientSecretSharedKey, message);
            // Encrypt
            EncryptParams encParam = Utilities.encryptMessage(clientAesKey, message);

            byte[] ciphertext = encParam.ciphertext;
            byte[] encodedParams = encParam.encodedParams;
            // create a destination array that is the size of the two arrays
            byte[] destination = new byte[ciphertext.length + encodedParams.length];
            // copy ciphertext into start of destination (from pos 0, copy ciphertext.length bytes)
            System.arraycopy(ciphertext, 0, destination, 0, ciphertext.length);
            // copy encodedParams into end of destination (from pos ciphertext.length, copy encodedParams.length bytes)
            System.arraycopy(encodedParams, 0, destination, ciphertext.length, encodedParams.length);
 
            // Send encrypted message
            dOut.writeInt(destination.length); // write length of the message
            dOut.write(destination);           // write the message
            dOut.flush();

            // Send HMAC
            dOut.writeInt(hmacSha256.length); // write length of the message
            dOut.write(hmacSha256);           // write the message
            dOut.flush();
        } catch (Exception e) {
            System.out.println("Caught exception at " + e.toString());
        }
    }

    private static byte[] receiveSecureMessageFromServer(Clientv2 client, byte[] clientSecretSharedKey)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
        SecretKeySpec clientAesKey = new SecretKeySpec(clientSecretSharedKey, 0, 16, "AES");
        
        byte[] louco = new byte[1000];
        try {
            byte[] concat = receiveBytesFromServer(client);
            byte[] hmac = receiveBytesFromServer(client);

            int len = concat.length;
            int posCipher = len - 18;

            byte[] ciphertext = new byte[posCipher];
            System.arraycopy(concat, 0, ciphertext, 0, posCipher);
            byte[] encodedParams = new byte[18];
            System.arraycopy(concat, posCipher, encodedParams, 0, 18);

            byte[] messageDecrypt = Utilities.decryptMode(clientAesKey, encodedParams, ciphertext);
            String decryptMessage = new String(messageDecrypt, StandardCharsets.UTF_8);

            // Verify HMAC
            byte[] hmacDecryptMessage = Utilities.HmacSha256(clientSecretSharedKey, decryptMessage.getBytes("UTF-8"));
            if (Arrays.equals(hmac, hmacDecryptMessage)) {
                return messageDecrypt;
            } else {
                System.out.println("\r\nHMAC does not match!");
                return louco;
            }
        } catch (Exception e) {
            System.out.println("Caught exception at " + e.toString());
            return null;
        }
        
    }

    private static void sendMSGtoServer (Clientv2 client, Scanner sc, byte[] clientSecretSharedKey, String username) throws IOException, InvalidKeyException, NoSuchAlgorithmException,
    InvalidKeySpecException, IllegalStateException, InvalidAlgorithmParameterException, NoSuchPaddingException,
    IllegalBlockSizeException, BadPaddingException {

        SecretKeySpec clientAesKey = new SecretKeySpec(clientSecretSharedKey, 0, 16, "AES");
        String ipServer = client.socket.getInetAddress().toString().replace("/", "");
        System.out.print("\r\nYou are now connected to "+ipServer+"!\n\n");
        System.out.print(username+"@"+ipServer+":# ");
        String input = sc.nextLine();
        
        try {
            DataOutputStream dOut = new DataOutputStream(client.socket.getOutputStream());

            while (true) 
            {
                // Calculate HMAC SHA 256
                byte[] hmacSha256 = Utilities.HmacSha256(clientSecretSharedKey, input.getBytes("UTF-8"));

                //EncryptParams encParam = Utilities.encryptMessage(clientAesKey, "Pedro");
                EncryptParams encParam = Utilities.encryptMessage(clientAesKey, input.getBytes("UTF-8"));

                byte[] ciphertext = encParam.ciphertext;
                byte[] encodedParams = encParam.encodedParams;

                // System.out.println("Length encoded: " + encodedParams.length); 18

                // create a destination array that is the size of the two arrays
                byte[] destination = new byte[ciphertext.length + encodedParams.length];

                // copy ciphertext into start of destination (from pos 0, copy ciphertext.length bytes)
                System.arraycopy(ciphertext, 0, destination, 0, ciphertext.length);

                // copy encodedParams into end of destination (from pos ciphertext.length, copy encodedParams.length bytes)
                System.arraycopy(encodedParams, 0, destination, ciphertext.length, encodedParams.length);

                //System.out.println("Send: " + Utilities.toHexString(destination));
                
                // Send encrypted message
                dOut.writeInt(destination.length); // write length of the message
                dOut.write(destination);           // write the message
                dOut.flush();

                // Send HMAC
                dOut.writeInt(hmacSha256.length); // write length of the message
                dOut.write(hmacSha256);           // write the message
                dOut.flush();

                if (input.equals("exit")) {
                    System.out.println("..........Closing Connection..........");
                    sc.close();
                    return;
                }
                
                while (!input.equals("exit")) {
                    int buff = feedbackFromServer(client);
                    if (buff == 0) break;
                }
                
                System.out.print(username+"@"+ipServer+":# ");
                input = sc.nextLine();   
            }

        } catch (IOException i) 
        {
            System.out.println(i);
        }
        client.socket.close();
    }

    private static int feedbackFromServer (Clientv2 client) throws IOException {
        BufferedReader in = new BufferedReader(new InputStreamReader(client.socket.getInputStream()));
        String data = null;
       
        try { 
            if((data = in.readLine()) != null)
            {
                if (data.equals("end")) {
                    //System.out.println("Entrei Aqui");
                    return 0;
                }
                System.out.println(data);
                return 1;
                //byte[] sms = receiveBytesFromServer(client);
                //if (sms.length != 0) return 0;
            } else {
                return 0;
            }
        } catch (IOException i) {
            System.out.println("Caught Exception: " + i.toString());
            return -1;
        }
    }

    /**
     * @return public key
     **/
    private static byte[] getPubKey() 
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

            return encKey;
        } 
        catch (Exception e) 
        {
            System.out.println("Caught exception: " + e.toString());
            return null;
        }
    }

    /**
     * @return private key
     **/
    private static PrivateKey getPrivKey() 
    {
        try 
        {
            // get pub key and send it to the Server
            FileInputStream keyfis = new FileInputStream("priv_key");
            byte[] encKey = new byte[keyfis.available()];
            keyfis.read(encKey);
            keyfis.close();

            PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(encKey);

            KeyFactory keyFactory = KeyFactory.getInstance("DSA");
            PrivateKey privKey = keyFactory.generatePrivate(privKeySpec);

            return privKey;
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

    private static byte[] receiveServerPubKey(Clientv2 client) throws IOException {
        try {
            DataInputStream dIn = new DataInputStream(client.socket.getInputStream());

            int length = dIn.readInt();   
            byte[] message = new byte[length];      
            if(length > 0) {
                dIn.readFully(message, 0, message.length);             
            }

            return message;
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
            out.println(pk_client);
            out.flush();
        } 
        catch (Exception e)
        {
            System.out.println("Caught exception: " + e.toString());
        }

    }

    public static void main(String[] args) throws Exception 
    {
        int port = 50172;
        String input = args[0];
        int posArroba = input.indexOf("@");
        String username = input.substring(0, posArroba);
        String ipaddr = input.substring(posArroba+1, input.length());
        Clientv2 client = new Clientv2(InetAddress.getByName(ipaddr), port);
        //Check and/or create file with public key
        File f = new File("pub_key");
        if (!f.isFile()) 
        {
            GenKeyPairs genKeys = new GenKeyPairs();
            genKeys.genKeyPairs();
			System.out.println("Par criado");
        }

        //Ligar ao Servidor
        System.out.println("\r\nTrying to connect to Server: " + client.socket.getInetAddress());
        client.start(client, username);
    }
}