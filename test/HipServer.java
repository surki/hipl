import java.net.Socket;
import java.net.ServerSocket;
import java.net.InetSocketAddress;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.BufferedReader;
import java.io.PrintWriter;
import java.io.InputStreamReader;
import javax.net.ServerSocketFactory;
import jip.HipSocketImplFactory;
import jip.HipServerSocketFactory;

public class HipServer {

    public static void main (String[] args) {
	try {
	    // begin GLOB
	    //ServerSocket.setSocketFactory(new HipSocketImplFactory());
	    //Socket.setSocketImplFactory(new HipSocketImplFactory());
	    // end GLOB
	    // begin PC
	    ServerSocketFactory hipFactory = new HipServerSocketFactory();
	    // end PC
	    if (args.length != 1 && args.length != 2) {
		System.err.println("Usage: HipServer <port> [<local_addr>]");
		System.exit(1);
	    }
	    int port = Integer.parseInt(args[0]);
	    // begin GLOB
	    //ServerSocket ss = new ServerSocket();
	    // end GLOB
	    // begin PC
	    ServerSocket ss = hipFactory.createServerSocket();
	    // end PC
	    if (args.length == 1)
		ss.bind(new InetSocketAddress(port));
	    else
		ss.bind(new InetSocketAddress(args[1], port));
	    System.out.println(ss.toString());
	    Socket s = ss.accept();
	    System.out.println(s.toString());
	    InputStream is = s.getInputStream();
	    System.out.println(is.toString());
	    BufferedReader in = new BufferedReader(new InputStreamReader(is));
	    OutputStream os = s.getOutputStream();
	    System.out.println(os.toString());
	    PrintWriter out = new PrintWriter(os);
	    String line;
	    while ((line = in.readLine()) != null) {
		System.out.println("Received: " + line);
		out.println(line);
		out.flush();
	    }
	} catch (Exception ex) {
	    ex.printStackTrace();
	}
    }

}
