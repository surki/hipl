/*
 * Author:    Jaakko Kangasharju
 * Copyright: GNU/GPL 2004
 */

package jip;

import java.net.Socket;
import java.net.SocketException;

/**
 * A socket implementation for the HIP protocol.  This class is for
 * use with the JIP per-connection API.  These sockets are created
 * with the {@link HipSocketFactory} according to the {@link
 * javax.net} socket extensibility package interface.
 *
 * @author Jaakko Kangasharju
 */
public class HipSocket extends Socket {

    HipSocketImpl impl;

    HipSocket (HipSocketImpl impl) throws SocketException {
	super(impl);
	this.impl = impl;
	impl.create(true);
    }

    native void klugeAccept ();

    /**
     * Bind this socket to a local HIP endpoint.  This method does
     * what the normal {@link #bind} method with the difference that
     * it takes a {@link HipAddress} object directly.  This method is
     * required when using application-specified endpoints.
     */
    public void bind (HipAddress addr, int port) {
	impl.bind(addr, port);
    }

}
