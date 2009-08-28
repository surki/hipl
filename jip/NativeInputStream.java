/*
 * Author:    Jaakko Kangasharju
 * Copyright: GNU/GPL 2004
 */

package jip;

import java.io.InputStream;

/**
 * An input stream wrapping a Unix file descriptor.  Input code using
 * the Java Native Interface often has only file descriptors available
 * in the native code, but Java really wants a {@link InputStream}.
 * This class implements reading from a Unix file descriptor in the
 * Java style.
 *
 * @author Jaakko Kangasharju
 */
public class NativeInputStream extends InputStream {

    private int fd = -1;

    private static native void nativeInit ();

    private native int internalRead (byte[] b, int off, int len);

    static {
	System.loadLibrary("jip");
	nativeInit();
    }

    /**
     * Construct a stream from a file descriptor.  The given file
     * descriptor may refer to anything that supports the
     * <code>read</code> function, e.g. a file or a socket.
     *
     * @param fd the file descriptor to wrap
     */
    NativeInputStream (int fd) {
	this.fd = fd;
    }

    public int read () {
	byte[] data = new byte[1];
	if (read(data, 0, 1) == 1) {
	    return data[0];
	} else {
	    return -1;
	}
    }

    public int read (byte[] b, int off, int len) {
	if (b == null) {
	    throw new NullPointerException();
	}
	if (off < 0 || len < 0 || off + len > b.length) {
	    throw new IndexOutOfBoundsException();
	}
	return internalRead(b, off, len);
    }

}
