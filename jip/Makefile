# Makefile for "jip" Java HIP Resolver
#
# Author: Jaakko Kangasharju
# Licence: GNU/GPL 2004


# If this hasn't been set, we take as the default the directory where
# the Blackdown Debian packages place this.  If you're not on Debian,
# change this; none of us wants to set up autoconf.
#
ifndef JAVA_HOME
JAVA_HOME=/usr/lib/j2se/1.4
endif

JAVA_SOURCES=HipAddress.java HipSocket.java HipSocketFactory.java \
	HipServerSocket.java HipServerSocketFactory.java HipSocketImpl.java \
	HipSocketImplFactory.java NativeInputStream.java \
	NativeOutputStream.java
C_SOURCES=hip-address.c hip-socket-impl.c hip-socket.c native-stream.c
JAVA_CLASSES=$(patsubst %.java,jip/%.class,$(JAVA_SOURCES))
JAVA_HEADERS=jip_HipAddress.h jip_HipSocketImpl.h jip_HipSocket.h jip_NativeInputStream.h jip_NativeOutputStream.h
CFLAGS+=-Wall -W -I../libhipcore/ -I../tools -I../libinet6/include -I../libhiptool/include -I.. -I../linux/include -I../linux/net/ipv6/hip -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux

LDFLAGS+=-L../libhipcore/.libs -L../libinet6/.libs -L../libhiptool/.libs

APIDOCDIR=../doc/jip-api

all: jip.jar libjip.so

../libinet6/.libs/libinet6.so:
	make -C ../libinet6 libinet6.so

jip.jar: $(JAVA_SOURCES)
	javac $(JAVA_SOURCES)
	cd ..; jar cf jip/jip.jar $(JAVA_CLASSES)

libjip.so: $(C_SOURCES) $(JAVA_HEADERS) ../libhipcore/.libs/libhipcore.so ../libinet6/.libs/libinet6.so ../libhiptool/.libs/libhiptool.so
	gcc $(CFLAGS) $(LDFLAGS) -shared $(C_SOURCES) -hipcore -linet6 -lhiptool -o $@

$(JAVA_HEADERS): jip_%.h: jip.jar %.class
	javah -classpath jip.jar jip.$*

apidoc: $(APIDOCDIR)/index.html

$(APIDOCDIR)/index.html: $(JAVA_SOURCES) package.html
	mkdir -p $(APIDOCDIR)
	cd ..; javadoc -d jip/$(APIDOCDIR) -use -author -doctitle \
		"The HIPL Java API" -windowtitle "The HIPL Java API" \
		-linkoffline http://java.sun.com/j2se/1.4/docs/api jip \
		-sourcepath . jip

clean:
	rm -f *.class jip.jar libjip.so jip_*.h
	rm -f *~ core
	rm -rf $(APIDOCDIR)
