/*
 * Author:    Jaakko Kangasharju
 * Copyright: GNU/GPL 2004
 */

package jip;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import javax.net.ServerSocketFactory;

/**
 * A socket factory for creating HIP server sockets.  This class is
 * for use with the JIP per-connection API.  It creates {@link
 * ServerSocket} objects according to the {@link javax.net} socket
 * extensibility package interface.
 *
 * <p>Note: In the future, this class may acquire methods taking a
 * {@link HipAddress} object to bind to.
 *
 * @author Jaakko Kangasharju
 */
public class HipServerSocketFactory extends ServerSocketFactory {

    private HipSocketImplFactory factory = new HipSocketImplFactory();

    public ServerSocket createServerSocket () throws IOException {
	HipServerSocket ss = new HipServerSocket(factory);
	return ss;
    }

    public ServerSocket createServerSocket (int port) throws IOException {
	HipServerSocket ss = new HipServerSocket(factory);
	ss.bind(new InetSocketAddress((InetAddress) null, port));
	return ss;
    }

    public ServerSocket createServerSocket (int port, int backlog)
	throws IOException {
	HipServerSocket ss = new HipServerSocket(factory);
	ss.bind(new InetSocketAddress((InetAddress) null, port), backlog);
	return ss;
    }

    public ServerSocket createServerSocket (int port, int backlog,
					    InetAddress ifAddress)
	throws IOException {
	HipServerSocket ss = new HipServerSocket(factory);
	ss.bind(new InetSocketAddress(ifAddress, port), backlog);
	return ss;
    }

}
