
import java.io.*;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.math.BigInteger;
import java.util.Scanner;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import java.io.PrintWriter;
import java.lang.reflect.Array;
import java.security.SecureRandom;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
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

    private void listen() throws Exception {
        
        DBUtilities db = new DBUtilities();
        Socket client = this.server.accept();
        String clientAddress = client.getInetAddress().getHostAddress();
        System.out.println("\r\nNew connection from " + clientAddress);

        // Receber chave pública do cliente
        byte[] pubKeyClient = receiveBytesFromClient(client);
        System.out.println("\r\nPublic Key of Client:" + Utilities.toHexString(pubKeyClient));

        // Receber o nome do utilizador a que o cliente se quer ligar
        byte[] username = receiveBytesFromClient(client);
        String usernameToString = new String(username, StandardCharsets.UTF_8);
        System.out.println("\r\nUsername: " + usernameToString);

        // Verificar se o user a que o cliente se quer ligar, existe
        int userCount = db.verifyUserExists(usernameToString);
        if (userCount > 0) { // O utilizador existe
            sendBytesToClient(client, "valid".getBytes("UTF-8"));
            // 1. Gera par de chaves Diffie Helman
            byte[] pubKeyServer = DH_Server.getServerPubKeyEnc();
            System.out.println("\r\nPub key sent to client: " + Utilities.toHexString(pubKeyServer));
            // 2. Enviar a pubkeyDH para o cliente
            sendBytesToClient(client, pubKeyServer);
            // 5. Receber pubKeyDH do cliente
            byte[] pubKeyDHClient = receiveBytesFromClient(client);
            System.out.println("\r\nPub key received from client: " + Utilities.toHexString(pubKeyDHClient));
            // 7. Gerar chave secreta partilhada
            byte[] serverSecretSharedKey = DH_Server.getServerSharedSecretKey(pubKeyDHClient);
            System.out.println("\r\nShared secret key: " + Utilities.toHexString(serverSecretSharedKey));

            /*******************************CANAL SEGURO********************************/

            // Verificar se a Public Key do Cliente está na tabela das chaves autorizadas
            String sClientPk = Utilities.getPublicKey(pubKeyClient).toString();
            int userID = db.selectIDUser(usernameToString);
            //System.out.println("User ID: " + userID);
            //String sPK = db.selectPKAuthKeys(userID);
            //System.out.println("PK BD: " + sPK);
            //System.out.println("PK Client: " + sClientPk);
            int count = db.verifyPKAuthKeys(sClientPk, userID);
            //System.out.println("Count users: " + count);
            String verified = "NOK";
            // Se for uma chave autorizada, Então:
            if (count > 0) {
                // Enviar metodo de autenticação
                String method = "pk_auth";
                sendSecureMessageToClient(client,serverSecretSharedKey,method.getBytes("UTF-8"));
                // Enviar Nonce para o cliente assinar
                byte[] nonce = Utilities.nonce();
                //sendSecureMessageToClient(client, serverSecretSharedKey, nonce);
                sendBytesToClient(client, nonce);
                // Receber assinatura
                //byte[] signature = receiveSecureMessageFromClient(client, serverSecretSharedKey);
                byte[] signature = receiveBytesFromClient(client);
                // Verificar se a assinatura é válida
                boolean verifies = Utilities.verifySignature(Utilities.getPublicKey(pubKeyClient), signature, nonce);

                if (verifies) { // Cliente autenticado
                    System.out.println("\r\nVerified: OK!");
                    verified = "OK";
                } else {
                    System.out.println("\r\nVerified: Invalid!");
                    verified = "Exit";
                }
    
                // Send confirmation to Client
                sendSecureMessageToClient(client, serverSecretSharedKey, verified.getBytes("UTF-8"));
            } else {
                int nTentativas = 3;
                // Enviar metodo de autenticação
                String method = "pass";
                sendSecureMessageToClient(client, serverSecretSharedKey, method.getBytes("UTF-8"));
                do {
                    // Pedir a password do user a que o client se quer ligar
                    String enterPw = "Enter password for "+usernameToString+": ";
                    sendSecureMessageToClient(client, serverSecretSharedKey, enterPw.getBytes("UTF-8"));
                    // Verificar se a password recebida coincide com a password do user
                    byte[] password = receiveSecureMessageFromClient(client, serverSecretSharedKey);
                    String passwordToString = new String(password, StandardCharsets.UTF_8);
                    //System.out.println("Password recebida: " + passwordToString);
                    String passwordUser = db.selectPWUser(userID);
                    String salt = db.selectSaltUser(userID);
                    passwordToString = DBUtilities.getHash(DBUtilities.getHex(password), salt);
                    //System.out.println("Password com salt: " + passwordToString);
                    //System.out.println("Password com salt USER: " + passwordUser);
                    // 3.3 Se SIM:
                    nTentativas--;
                    if (passwordUser.equals(passwordToString)) {
                        // Adicionar a Pub Key do cliente à lista de chaves autorizadas
                        db.insertAuthKeys(userID, clientAddress, sClientPk);
                        // Send confirmation to Client
                        //System.out.println("Password Correta!");
                        verified = "OK";
                        sendSecureMessageToClient(client, serverSecretSharedKey, verified.getBytes());
                    } else {
                        //System.out.println("Password Incorreta!");
                        if (nTentativas == 0) {
                            // Send message to Client
                            verified = "Exit";
                            sendSecureMessageToClient(client, serverSecretSharedKey, verified.getBytes());
                            break;
                        }
                        // Send confirmation to Client
                        verified = "NOK";
                        sendSecureMessageToClient(client, serverSecretSharedKey, verified.getBytes());
                    }
                } while (verified.equals("NOK"));
            }

            if (verified.equals("OK")) {
                receiveClientMSG(client, clientAddress, serverSecretSharedKey);
            } else {
                client.close();
            }

        } else { // O utilizador não existe
            sendBytesToClient(client, "invalid".getBytes("UTF-8"));
            client.close();
        }   
    }

    /**
     * Receives the pub key to the Server
     * 
     * @param client
     * @return
     * @throws IOException
     **/

    private static byte[] receiveBytesFromClient(Socket client) throws IOException {
        try {
            DataInputStream dIn = new DataInputStream(client.getInputStream());

            int length = dIn.readInt();
            byte[] message = new byte[length]; // read length of incoming message
            if (length > 0) {
                dIn.readFully(message, 0, message.length); // read the message~
            }
            return message;
        } catch (Exception e) {
            System.out.println("Caught exception: " + e.toString());
            return null;
        }
    }

    private static void receiveClientMSG(Socket client, String clientAddress, byte[] serverSecretSharedKey)
            throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, InterruptedException {

        PrintWriter out = new PrintWriter(client.getOutputStream(), true);
        SecretKeySpec serverAesKey = new SecretKeySpec(serverSecretSharedKey, 0, 16, "AES");
        // String mensagem = "recebido";

        try {
            int len = 1;
            while (len > 0) {
                byte[] concat = receiveBytesFromClient(client);

                byte[] hmac = receiveBytesFromClient(client);

                // System.out.println("Message: " + Utilities.toHexString(concat));

                len = concat.length;
                int posCipher = len - 18;

                byte[] ciphertext = new byte[posCipher];
                System.arraycopy(concat, 0, ciphertext, 0, posCipher);

                byte[] encodedParams = new byte[18];
                System.arraycopy(concat, posCipher, encodedParams, 0, 18);

                byte[] messageDecrypt = Utilities.decryptMode(serverAesKey, encodedParams, ciphertext);

                String decryptMessage = new String(messageDecrypt, StandardCharsets.UTF_8);

                // Verify HMAC
                byte[] hmacDecryptMessage = Utilities.HmacSha256(serverSecretSharedKey,
                        decryptMessage.getBytes("UTF-8"));
                if (Arrays.equals(hmac, hmacDecryptMessage)) {
                    System.out.println("\r\nHMAC mathes!");
                } else {
                    System.out.println("\r\nHMAC does not match!");
                }

                if (decryptMessage.equals("kys")) {
                    end(client);
                } else if (decryptMessage.equals("exit")) {
                    // System.out.println("Entrei no exit");
                    client.close();
                    return;
                } else {
                    System.out.println("\r\nMessage from " + clientAddress + ": " + decryptMessage);
                    
                    String osname = Utilities.getOsSystem();
                    System.out.println("SO: " + osname);

                    String command = "";
                    if (osname.contains("win")) {
                        command = "cmd /c " + decryptMessage;
                    } else { // Ubuntu/Mac
                        command = "/bin/sh -c " + decryptMessage;
                    }
                    
                    try {
                        Process process = Runtime.getRuntime().exec(command);

                        StringBuffer sf = new StringBuffer();

                        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                        
                        String line;
                        while ((line = reader.readLine()) != null) {
                            System.out.println(line);
                            sf.append(line + "\n");
                        }
                      
                        reader.close();
                        System.out.println("TERMINEI!");
                        // Enviar mensagem para o servidor
                        byte[] msg = String.valueOf(sf).getBytes("UTF-8");
                        sendSecureMessageToClient(client, serverSecretSharedKey, msg);               
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        } catch (IOException i) {
            System.out.println("Caught Exception: " + i.toString());
        }
    }

    private static void sendBytesToClient(Socket client, byte[] message) {
        try {
            DataOutputStream dOut = new DataOutputStream(client.getOutputStream());

            dOut.writeInt(message.length); // write length of the message
            dOut.write(message); // write the message
            dOut.flush();
            //System.out.println("Enviado com sucesso!");
        } catch (Exception e) {
            System.out.println("Caught exception: " + e.toString());
        }
    }

    private static void sendSecureMessageToClient(Socket client, byte[] serverSecretSharedKey, byte[] message) {

        SecretKeySpec serverAesKey = new SecretKeySpec(serverSecretSharedKey, 0, 16, "AES");

        try {
            DataOutputStream dOut = new DataOutputStream(client.getOutputStream());

            // Calculate HMAC SHA 256
            byte[] hmacSha256 = Utilities.HmacSha256(serverSecretSharedKey, message);
            // Encrypt
            EncryptParams encParam = Utilities.encryptMessage(serverAesKey, message);

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

    private static byte[] receiveSecureMessageFromClient(Socket client, byte[] serverSecretSharedKey)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
        SecretKeySpec serverAesKey = new SecretKeySpec(serverSecretSharedKey, 0, 16, "AES");
        
        byte[] louco = new byte[1000];
        try {
            byte[] concat = receiveBytesFromClient(client);
            byte[] hmac = receiveBytesFromClient(client);

            int len = concat.length;
            int posCipher = len - 18;

            byte[] ciphertext = new byte[posCipher];
            System.arraycopy(concat, 0, ciphertext, 0, posCipher);
            byte[] encodedParams = new byte[18];
            System.arraycopy(concat, posCipher, encodedParams, 0, 18);

            byte[] messageDecrypt = Utilities.decryptMode(serverAesKey, encodedParams, ciphertext);
            String decryptMessage = new String(messageDecrypt, StandardCharsets.UTF_8);

            // Verify HMAC
            byte[] hmacDecryptMessage = Utilities.HmacSha256(serverSecretSharedKey, decryptMessage.getBytes("UTF-8"));
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

    public InetAddress getSocketAddress() {
        return this.server.getInetAddress();
    }

    public int getPort() {
        return this.server.getLocalPort();
    }

    public static void end(Socket client) {
        System.out.println("..........Closing Server..........");
        try {
            client.close();
            System.exit(0);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public static void main(String[] args) throws Exception {
        // criar chaves.
        //File f = new File("pub_key");
        //if (!f.isFile()) {
        //    GenKeyPairs genKeys = new GenKeyPairs();
        //    genKeys.genKeyPairs();
        //    System.out.println("Par criado");
        //}

        // Criar servidor:
        Serverv2 app = new Serverv2(args[0]);
        System.out.println(
                "\r\nRunning Server: " + "Host=" + app.getSocketAddress().getHostAddress() + " Port=" + app.getPort());
        System.out.println("Waiting...");

        // Começar a ouvir:
        while (true) {
            app.listen();
            System.out.println("Previous Connection Closed.");
            System.out.println("Waiting for more connections...");
        }
    }
}