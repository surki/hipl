/*
 * Author:    Jaakko Kangasharju
 * Copyright: GNU/GPL 2004
 */

package jip;

import java.io.IOException;
import java.net.Socket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import javax.net.SocketFactory;

/**
 * A socket factory for creating HIP sockets.  This class is for use
 * with the JIP per-connection API.  It creates {@link Socket} objects
 * according to the {@link javax.net} socket extensibility package
 * interface.
 *
 * <p>Note: In the future, this class may acquire methods taking a
 * {@link HipAddress} object to bind to.
 *
 * @author Jaakko Kangasharju
 */
public class HipSocketFactory extends SocketFactory {

    private HipSocketImplFactory factory = new HipSocketImplFactory();

    public Socket createSocket () throws IOException {
	return new HipSocket((HipSocketImpl) factory.createSocketImpl());
    }

    public Socket createSocket (String host, int port)
	throws IOException {
	Socket s = new HipSocket((HipSocketImpl) factory.createSocketImpl());
	s.connect(new InetSocketAddress(host, port));
	return s;
    }

    public Socket createSocket (String host, int port, InetAddress localHost,
				int localPort)
	throws IOException {
	Socket s = new HipSocket((HipSocketImpl) factory.createSocketImpl());
	s.bind(new InetSocketAddress(localHost, localPort));
	s.connect(new InetSocketAddress(host, port));
	return s;
    }

    public Socket createSocket (InetAddress host, int port)
	throws IOException {
	Socket s = new HipSocket((HipSocketImpl) factory.createSocketImpl());
	s.connect(new InetSocketAddress(host, port));
	return s;
    }

    public Socket createSocket (InetAddress host, int port,
				InetAddress localHost, int localPort)
	throws IOException {
	Socket s = new HipSocket((HipSocketImpl) factory.createSocketImpl());
	s.bind(new InetSocketAddress(localHost, localPort));
	s.connect(new InetSocketAddress(host, port));
	return s;
    }

}
