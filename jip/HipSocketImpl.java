/*
 * Author:    Jaakko Kangasharju
 * Copyright: GNU/GPL 2004
 */

package jip;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.net.SocketImpl;
import java.net.InetAddress;
import java.net.SocketAddress;
import java.net.InetSocketAddress;

/**
 * A socket implementation using HIP as its protocol.  This class is
 * for use with the JIP global API.  It implements a HIP-specific
 * socket in the standard Java manner, by extending the {@link
 * SocketImpl} class.  An application should never create objects of
 * this class directly, but rather install the {@link
 * HipSocketImplFactory} as the socket creator.
 *
 * @author Jaakko Kangasharju
 */
public class HipSocketImpl extends SocketImpl {

    private final static char hexDigits[] = { '0', '1', '2', '3', '4', '5',
					      '6', '7', '8', '9', 'A', 'B',
					      'C', 'D', 'E', 'F' };

    private static String toHex (byte b) {
	return (new Character(hexDigits[(b & 0xF0) >> 4])).toString()
	    + hexDigits[b & 0x0F];
    }

    static {
	System.loadLibrary("jip");
	nativeInit();
    }

    private int native_fd = -1;

    private native static void nativeInit ();

    private void dump () {
	System.out.println("HipSocket dump: " + this);
	System.out.println("  native_fd:    " + native_fd);
	System.out.println("  address:      " + address);
	System.out.println("  fd:           " + fd);
	System.out.println("  localport:    " + localport);
	System.out.println("  port:         " + port);
    }

    private void setAddress (byte[] raw) {
	try {
	    System.out.print("Calling setAddress: ");
	    for (int i = 0; i < raw.length; i++) {
		System.out.print(toHex(raw[i]));
	    }
	    System.out.println();
	    address = InetAddress.getByAddress(raw);
	} catch (Exception ex) {
	    /*
	     * This is only called when we know we have a proper address
	     */
	}
    }

    public native void create (boolean stream);

    /**
     * Bind this socket to a HIP endpoint and a port.  This is the
     * lowest-level method for binding in this class.
     *
     * @param address the HIP endpoint to bind to
     * @param port the port number to bind to
     */
    public native void bind (HipAddress address, int port);

    /**
     * Connect this socket to a HIP endpoint and a port.  This is the
     * lowest-level method for connecting in this class.
     *
     * @param address the HIP endpoint to connect to
     * @param port the port number to connect to
     */
    public native void connect (HipAddress address, int port);

    public void bind (InetAddress address, int port) {
	bind(HipAddress.getByAddress(address), port);
    }

    public void bind (String host, int port) {
	bind(HipAddress.getByName(host), port);
    }

    public void connect (InetAddress address, int port) {
	connect(HipAddress.getByAddress(address), port);
    }

    public void connect (String host, int port) {
	connect(HipAddress.getByName(host), port);
    }

    public void connect (SocketAddress address, int timeout) {
	InetSocketAddress sa = (InetSocketAddress) address;
	if (timeout < 0) {
	    timeout = 0;
	}
	Object oldTimeout = getOption(SO_TIMEOUT);
	setOption(SO_TIMEOUT, new Integer(timeout));
	connect(sa.getHostName(), sa.getPort());
	if (oldTimeout != null) {
	    setOption(SO_TIMEOUT, oldTimeout);
	}
    }

    public native void listen (int backlog);

    public native void accept (SocketImpl s);

    public InputStream getInputStream () throws IOException {
	if (native_fd < 0) {
	    throw new IOException("Socket not initialized");
	}
	return new NativeInputStream(native_fd);
    }

    public OutputStream getOutputStream () throws IOException {
	if (native_fd < 0) {
	    throw new IOException("Socket not initialized");
	}
	return new NativeOutputStream(native_fd);
    }

    public native int available ();

    public native void close ();

    public boolean supportsUrgentData () {
	return true;
    }

    public native void sendUrgentData (int data);

    public native Object getOption (int id);

    public native void setOption (int id, Object value);

}
