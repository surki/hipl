import java.net.Socket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.BufferedReader;
import java.io.PrintWriter;
import java.io.InputStreamReader;
import javax.net.SocketFactory;
import jip.HipSocketImplFactory;
import jip.HipSocketFactory;

public class HipClient {

    public static void main (String[] args) {
	try {
	    // begin GLOB
	    //Socket.setSocketImplFactory(new HipSocketImplFactory());
	    // end GLOB
	    // begin PC
	    SocketFactory hipFactory = new HipSocketFactory();
	    // end PC
	    if (args.length != 3) {
		System.err.println("Usage: HipClient <host> <port> "
				   + "<localport>");
		System.exit(1);
	    }
	    String host = args[0];
	    int port = Integer.parseInt(args[1]);
	    int localport = Integer.parseInt(args[2]);
	    // begin GLOB
	    //Socket s = new Socket();
	    // end GLOB
	    // begin PC
	    Socket s = hipFactory.createSocket();
	    // end PC
	    s.bind(new InetSocketAddress(localport));
	    s.connect(new InetSocketAddress(host, port));
	    System.out.println(s.toString());
	    InputStream is = s.getInputStream();
	    System.out.println(is.toString());
	    BufferedReader in =
		new BufferedReader(new InputStreamReader(System.in));
	    BufferedReader sin = new BufferedReader(new InputStreamReader(is));
	    OutputStream os = s.getOutputStream();
	    System.out.println(os.toString());
	    PrintWriter sout = new PrintWriter(os);
	    String line;
	    System.out.println("Type your input, line by line");
	    while ((line = in.readLine()) != null) {
		sout.println(line);
		sout.flush();
		line = sin.readLine();
		System.out.println("Received: " + line);
	    }
	} catch (Exception ex) {
	    ex.printStackTrace();
	}
    }

}
