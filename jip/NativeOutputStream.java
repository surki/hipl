/*
 * Author:    Jaakko Kangasharju
 * Copyright: GNU/GPL 2004
 */

package jip;

import java.io.OutputStream;

/**
 * An output stream wrapping a Unix file descriptor.  Output code
 * using the Java Native Interface often has only file descriptors
 * available in the native code, but Java really wants a {@link
 * OutputStream}.  This class implements writing to a Unix file
 * descriptor in the Java style.
 *
 * @author Jaakko Kangasharju
 */
public class NativeOutputStream extends OutputStream {

    private int fd = -1;

    private static native void nativeInit ();

    private native void internalWrite (byte[] b, int off, int len);

    static {
	System.loadLibrary("jip");
	nativeInit();
    }

    /**
     * Construct a stream from a file descriptor.  The given file
     * descriptor may refer to anything that supports the
     * <code>write</code> function, e.g. a file or a socket.
     *
     * @param fd the file descriptor to wrap
     */
    NativeOutputStream (int fd) {
	this.fd = fd;
    }

    public void write (int b) {
	byte[] data = new byte[1];
	data[0] = (byte) (b & 0xFF);
	write(data, 0, 1);
    }

    public void write (byte[] b, int off, int len) {
	if (b == null) {
	    throw new NullPointerException();
	}
	if (off < 0 || len < 0 || off + len > b.length) {
	    throw new IndexOutOfBoundsException();
	}
	internalWrite(b, off, len);
    }

}
