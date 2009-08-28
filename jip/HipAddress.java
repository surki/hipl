/*
 * Author:    Jaakko Kangasharju
 * Copyright: GNU/GPL 2004
 */

package jip;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * A class representing a HIP endpoint.  The role this class plays in
 * JIP is comparable to that played by {@link InetAddress} in the
 * {@link java.net} socket system, i.e. these objects are what sockets
 * in JIP bind and connect to.  <code>HipAddress</code> objects are
 * constructed in various ways using static factory methods of this
 * class.
 *
 * <p>Note: This class should possibly be renamed to
 * <code>HipEndpoint</code>.
 *
 * @author Jaakko Kangasharju
 */
public class HipAddress {

    static {
	System.loadLibrary("jip");
	nativeInit();
    }

    private byte[] address = new byte[16];

    /*
     * I'm not yet sure how useful it would be for an application to
     * construct HipAddress objects itself.  The factory methods below
     * should suffice.
     */
    private HipAddress (byte[] address) {
	this.address = address;
    }

    private native static void nativeInit ();

    /**
     * Resolve a host name into all of its endpoints.  This method
     * resolves the given host name into all HIP endpoints that are
     * available for it.
     *
     * @param host the name of the host to resolve
     * @return an array of endpoints for <code>host</code>
     */
    public native static HipAddress[] getAllByName (String host);

    /**
     * Resolve a host name into an endpoint.  This method resolves the
     * given host name into a HIP endpoint for it.
     *
     * @param host the name of the host to resolve
     * @return an endpoint for <code>host</code>
     */
    public static HipAddress getByName (String host) {
	HipAddress ret[] = getAllByName(host);
	if (ret.length == 0)
	    return null;
	return ret[0];
    }

    /**
     * Transform an Internet address into all of the host's endpoints.
     * This method constructs an array of HIP endpoints for the given
     * {@link InetAddress} object.  A reverse resolving of the address
     * may be needed.
     *
     * <p>This method is useful mostly in legacy systems where {@link
     * InetAddress} objects get passed around.  Due to the design of
     * JIP, the {@link #getAllByName} method is preferable.
     *
     * @param addr the address of the host to transform
     * @return an array of endpoints for <code>addr</code>
     */
    public static HipAddress[] getAllByAddress (InetAddress addr) {
	return getAllByName(addr.getHostName());
    }

    /**
     * Transform an Internet address into the host's endpoint.  This
     * method constructs a HIP endpoint for the given {@link
     * InetAddress} object.  A reverse resolving of the address may be
     * needed.
     *
     * <p>This method is useful mostly in legacy systems where {@link
     * InetAddress} objects get passed around.  Due to the design of
     * JIP, the {@link #getByName} method is preferable.
     *
     * @param addr the address of the host to transform
     * @return an endpoint for <code>addr</code>
     */
    public static HipAddress getByAddress (InetAddress addr) {
	HipAddress ret[] = getAllByAddress(addr);
	if (ret.length == 0)
	    return null;
	return ret[0];
    }

    /**
     * Read an application-specified EID for a host.  This method
     * reads a private or a public key from a file, and constructs a
     * <code>HipAddress</code> representing the HIT.
     *
     * @param fileName the name of the file to read the key from
     * @return an object representing the given application-specified
     * endpoint
     */
    public native static HipAddress getFromFile (String fileName);

}
