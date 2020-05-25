import java.net.*;
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
            input = scanner.nextLine();

            PrintWriter out = new PrintWriter(this.socket.getOutputStream(), true);
            out.println(input);
            out.flush();
        }

        // close the connection
        try {
            socket.close();
        } catch (IOException i) {
            System.out.println(i);
        }
    }

    public static void main(String[] args) throws Exception 
    {
        Client client = new Client(InetAddress.getByName(args[0]), Integer.parseInt(args[1]));

        System.out.println("\r\nConnected to Server: " + client.socket.getInetAddress());
        client.start();
    }
}