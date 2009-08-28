/*
 * Author:    Jaakko Kangasharju
 * Copyright: GNU/GPL 2004
 */

package jip;

import java.net.SocketImpl;
import java.net.SocketImplFactory;

/**
 * A socket factory for getting HIP socket implementations.  This
 * class is for use with the JIP global API.  It creates {@link
 * SocketImpl} objects according to the socket extensibility interface
 * in the {@link java.net} package.
 *
 * @author Jaakko Kangasharju
 */
public class HipSocketImplFactory implements SocketImplFactory {

    public SocketImpl createSocketImpl () {
	return new HipSocketImpl();
    }

}
