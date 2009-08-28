/*
 * Author:    Jaakko Kangasharju
 * Copyright: GNU/GPL 2004
 */

package jip;

import java.io.IOException;
import java.net.Socket;
import java.net.ServerSocket;
import java.net.SocketAddress;
import java.net.InetSocketAddress;

/**
 * A server socket implementation for the HIP protocol.  This class is
 * for use with the JIP per-connection API.  These server sockets are
 * created with the {@link HipServerSocketFactory} according to the
 * {@link javax.net} socket extensibility package interface.
 *
 * <p>Due to the low-level nature of the HIP protocol, this server
 * socket implementation needs to override some additional
 * functionality of the normal {@link ServerSocket} class in Java.  If
 * any problems occur using this class as a normal {@link
 * ServerSocket}, that is a bug.  Also, because of this, the
 * implementation is currently tied to Sun's Java implementation (has
 * been tested with 1.4.2, examination indicates it should work with
 * 1.5.0 beta).
 *
 * @author Jaakko Kangasharju
 */
public class HipServerSocket extends ServerSocket {

    private HipSocketImplFactory factory;
    private HipSocketImpl impl;

    HipServerSocket (HipSocketImplFactory factory) throws IOException {
	this.factory = factory;
	impl = (HipSocketImpl) factory.createSocketImpl();
	impl.create(true);
    }

    public void bind (SocketAddress endpoint, int backlog) throws IOException {
	InetSocketAddress end = (InetSocketAddress) endpoint;
	impl.bind(HipAddress.getByAddress(end.getAddress()), end.getPort());
	impl.listen(backlog);
    }

    /**
     * Bind this socket to a local HIP endpoint.  This method acts
     * like {@link #bind(SocketAddress)} except that it takes a {@link
     * HipAddress} and a port number.  This method is required when
     * using application-specified endpoints.
     *
     * @param endpoint the endpoint to bind to
     * @param port the port number to bind to
     */
    public void bind (HipAddress endpoint, int port) {
	bind(endpoint, port, 50);
    }

    /**
     * Bind this socket to a local HIP endpoint with a specified
     * listening backlog.  This method acts like {@link
     * #bind(SocketAddress)} except that it takes a {@link HipAddress}
     * and a port number.  This method is required when using
     * application-specified endpoints.
     *
     * @param endpoint the endpoint to bind to
     * @param port the port number to bind to
     * @param backlog the listening backlog length
     */
    public void bind (HipAddress endpoint, int port, int backlog) {
	if (backlog < 1) {
	    backlog = 50;
	}
	impl.bind(endpoint, port);
	impl.listen(backlog);
    }

    public Socket accept () throws IOException {
	HipSocket s =
	    new HipSocket((HipSocketImpl) factory.createSocketImpl());
	HipSocketImpl si = s.impl;
	s.impl = null;
	impl.accept(si);
	s.impl = si;
	s.klugeAccept();
	return s;
    }

}
