#!/bin/sh -xv
# This script allows for building binary and source debian packages

#Default debian package is BINARY
TYPE=binary

#MAJOR=1
#MINOR=0
#VERSION="$MAJOR.$MINOR"
#RELEASE=4
VERSIONFILE="release.version"

# jk: added this to get the version from hipl-root/release-version
# assuming we're running this from the root Makefile. please link the
# file to the current path if not so
if [ ! -f $VERSIONFILE ]; then
    echo "No $VERSIONFILE found in current ("`pwd`") path!"
    exit 1
fi

VERSION=`grep ^Version: $VERSIONFILE|sed 's/^.*: //'`
RELEASE=`grep ^Release: $VERSIONFILE|sed 's/^.*: //'`
echo "Building release $VERSION-$RELEASE"

DEBARCH="i386"
if uname -m|grep x86_64; then DEBARCH=amd64; fi
# if uname -m|grep arm*; then DEBARCH=armel; fi 
if dpkg --print-architecture|grep armel;then DEBARCH=armel;fi

REVISION=`/usr/bin/lsb_release -c | /usr/bin/awk '{print $2}'`
# The latest SDK is diablo, the previous one - chinook. One may specify here whatever preferred more.
# Better, we have to find out how to detect SDK version installed on a PC automatically -- Andrey Khurri
if [ $DEBARCH = "armel" ]; then 
    # jk: this isn't by any way 100%, but works for now. just use the 
    # the first repository's revision
    
    REVISION=`grep '[^#]*deb http://repository.maemo.org/' /etc/apt/sources.list|head -n1|awk '{print $3}'|sed 's/\/.*$//'`
    if [ -z "$REVISION" ]; then
	REVISION=unknown;
    fi
    
    # this doesn't seem to get set by automake in maemo
    PYEXECDIR=/usr/lib/python2.5
fi

SUFFIX="-$VERSION-$RELEASE-$REVISION"
PKG_SUFFIX="-$VERSION-$RELEASE"
NAME=hipl
NAMEGPL=libhiptool
DEBIAN=${DEBARCH}/DEBIAN
DEBIANGPL=$DEBARCH/DEBIAN-hiptool
CORPORATE=
PKGROOT=$PWD/test/packaging
PKGDIR=$PKGROOT/${NAME}${PKG_SUFFIX}-deb
PKGDIR_SRC=$PKGROOT/${NAME}${PKG_SUFFIX}-deb-src
SRCDIR=${PKGDIR_SRC}/${NAME}${SUFFIX}
HIPL=$PWD
POSTFIX="deb"
# Comment this out if you want to install without sudo (see bug id 603)
if [ $DEBARCH != "armel" ]; then
    SUDO=sudo
fi

# The current debian compilation does not use a fresh copy of files,
# but instead relies on older execution of configure. Therefore $pyexecdir
# (from configure) points /usr/local/.. and we must remove the "local".
PYEXECDIR=`echo $PYEXECDIR|sed s/local//`

TMPNAME="${VERSION}-${RELEASE}-${REVISION}-${DEBARCH}"
if dpkg --print-architecture|grep armel;then TMPNAME="${VERSION}-${RELEASE}-${REVISION}-armel"; fi

PKGNAME="${NAME}-${TMPNAME}.${POSTFIX}"
TMP=""
DEBLIB="$NAME-$TMP"

LIBDEPS="libgtk2.0-0, libxml2, iptables, libsqlite3-0"
if [ $DEBARCH = "armel" ]; then
    if [ $REVISION = "diablo" ]; then
	LIBDEPS="$LIBDEPS, libssl0.9.8"
    else
	LIBDEPS="$LIBDEPS, libssl0.9.7"
    fi
else
    LIBDEPS="$LIBDEPS, libssl0.9.8, libcap2, libuuid1, libnet-dns-perl, libnet-ip-perl, libsocket6-perl, libio-socket-inet6-perl"
fi

LINE0="Depends:"
LINE1="Build-Depends:"
LINE2="Package:"
LINE3="Architecture:"

PKGDIRGPL=$PKGROOT/${NAMEGPL}-${VERSION}-deb
PKGNAMEGPL="${NAMEGPL}-${VERSION}-${RELEASE}-${DEBARCH}.deb"

DEFAULT_MODE=0755 # default umask
DEFAULT_OWNER=root # default owner root
DEFAULT_GROUP=root # default group root

copy()
{
    if test $# -ne 3
    then
	echo "Function 'copy' assumes three args"
	echo "Internal failure"
	exit 1
    fi

    $SUDO cp $@
    $SUDO chown $DEFAULT_OWNER:$DEFAULT_GROUP $3
    #$SUDO chmod $DEFAULT_MODE $3
}

remove()
{
    $SUDO rm $@
}

inst()
{
    if [ $DEBARCH = "armel" ]; then
	$SUDO install --mode=$DEFAULT_MODE $@
    else
	$SUDO install --mode=$DEFAULT_MODE --owner=$DEFAULT_OWNER --group=$DEFAULT_GROUP $@
    fi
}

# copy the tarball from the HIPL directory
copy_tarball ()
{
	set -e
	
	echo "** Copying the tarball"
	#cd ${PKGDIR}
        cp ${HIPL}/hipl-main.tar.gz ${PKGDIR_SRC}/${NAME}_${VERSION}.orig.tar.gz

	echo "** Copying Debian control files to '${SRCDIR}/debian'"

	inst -d "${SRCDIR}/debian"
	inst ${PKGROOT}/$DEBIAN/control-src ${SRCDIR}/debian/control
	for f in changelog copyright rules preinst postinst prerm postrm;do
		inst ${PKGROOT}/$DEBIAN/$f "${SRCDIR}/debian"
	done

        if [ x"$TMP" = x"firewall" ]; then
		inst -d "${SRCDIR}/debian"
		for f in preinst postinst prerm postrm;do
		inst "${PKGROOT}/$DEBIAN-FW/$f" "${SRCDIR}/debian"
		done
	fi

	
	set +e
}

# copy GPL files when building corporate packages
copy_files_gpl()
{
	echo "** Copying Debian control files to '$PKGDIRGPL/DEBIAN'"
	
	set -e

	inst -d "$PKGDIRGPL/DEBIAN"
	for f in control changelog copyright preinst postinst prerm postrm;do
		inst $DEBIANGPL/$f "$PKGDIRGPL/DEBIAN"
	done

        if [ $TMP = "firewall" ]; then
		inst -d "$PKGDIRGPL/DEBIAN-FW"
		for f in preinst postinst prerm postrm;do
			inst $DEBIANGPL/$f "$PKGDIRGPL/DEBIAN-FW"
		done
        fi

	
	
	echo "** Copying binary files to '$PKGDIRGPL'"
	inst -d "$PKGDIRGPL/usr"
	cd "$PKGDIRGPL"
	
	# create directory structure
	inst -d usr/lib
	cd "$HIPL"
	
	for suffix in a so so.0 so.0.0.0;do
		copy -d libhiptool/.libs/libhiptool.$suffix $PKGDIRGPL/usr/lib/
	done
	copy -L libhiptool/.libs/libhiptool.la $PKGDIRGPL/usr/lib/
	
	set +e
}

init_files ()
{
    echo "** Copying Debian control files to '$PKGDIR/DEBIAN'"
    set -e
    inst -d "$PKGDIR/DEBIAN"
    
    if [ $TMP = "daemon" ]; then
    	for f in preinst postinst prerm postrm;do
		inst $DEBIAN/$f "$PKGDIR/DEBIAN" 
    	done
    fi

    if [ $TMP = "lib" ]; then
	echo '#!/bin/sh' > $PKGDIR/DEBIAN/postinst
	chmod a+rx  $PKGDIR/DEBIAN/postinst
	echo "ldconfig" >> $PKGDIR/DEBIAN/postinst
    fi

  
    if [ $TMP = "firewall" ]; then
        for f in preinst postinst prerm postrm;do
	    inst $DEBIAN-FW/$f "$PKGDIR/DEBIAN" 
    	done
    fi

    if [ $TMP = "dnsproxy" ]; then
        for f in preinst postinst prerm postrm;do
	    inst $DEBIAN-dnsproxy/$f "$PKGDIR/DEBIAN" 
    	done
    fi

    for f in control changelog copyright;do
	inst $DEBIAN/$f "$PKGDIR/DEBIAN" 
    done

    echo "** Modifying Debian control file for "$DEBLIB" "$TMP" and "$DEBARCH""
    
    echo "Before:"
    cat $PKGDIR\/DEBIAN\/control

    if [ x"$DEBLIB" = x"" ]; then
	if [ x"$TMP" = x"lib" ]; then
	    echo "Adding main dependencies to hipl-lib"
     	    $SUDO sed -i '/'"$LINE0"'/a\'"$LINE0"' '"$LIBDEPS"'' $PKGDIR\/DEBIAN\/control
	else
	    echo "No dependency to hipl-lib"
     	    $SUDO sed -i '/'"$LINE0"'/d' $PKGDIR\/DEBIAN\/control
	fi
    else
	echo "Adding dependency to hipl-lib"
     	$SUDO sed -i '/'"$LINE1"'/a\'"$LINE0"' '"$DEBLIB"'' $PKGDIR\/DEBIAN\/control
    fi

    $SUDO sed -i '/'"$LINE2"'/ s/.*/&\-'"$TMP"'/' $PKGDIR\/DEBIAN\/control
    $SUDO sed -i 's/"$LINE3"/&'" $DEBARCH"'/' $PKGDIR\/DEBIAN\/control

    echo "After:"
    cat $PKGDIR\/DEBIAN\/control

}

# copy and build package files
copy_and_package_files ()
{
    echo "copying and packaging files"

    TMP="lib"
    DEBLIB=""
    init_files;
    
    echo "** Copying library files to '$PKGDIR'"
    inst -d "$PKGDIR/usr"
    cd "$PKGDIR"
   
    echo "$PKGDIR"

    inst -d usr/lib

    cd "$HIPL"
    
    echo "$HIPL"

    for suffix in a so so.0 so.0.0.0;do
	copy -d libinet6/.libs/libinet6.$suffix $PKGDIR/usr/lib/
	if [ ! "$CORPORATE" ];then
		copy -d libhiptool/.libs/libhiptool.$suffix $PKGDIR/usr/lib/
	fi
	copy -d libopphip/.libs/libopphip.$suffix $PKGDIR/usr/lib/
	copy -d libdht/.libs/libhipopendht.$suffix $PKGDIR/usr/lib/
    done

    copy -L libinet6/.libs/libinet6.la $PKGDIR/usr/lib/
	if [ ! "$CORPORATE" ];then
	    copy -L libhiptool/.libs/libhiptool.la $PKGDIR/usr/lib/
	fi
   
    copy -L libopphip/.libs/libopphip.la $PKGDIR/usr/lib/
    
    copy -L libdht/.libs/libhipopendht.la $PKGDIR/usr/lib/
    
    copy -d libhipgui/libhipgui.a $PKGDIR/usr/lib/

    PKGNAME="${NAME}-$TMP-${TMPNAME}.${POSTFIX}"
    create_sub_package;

    TMP="daemon"
    #hipl-daemon hipd: depends on hipl-lib
    DEBLIB="$NAME-lib"
    init_files;
    
    echo "** Copying binary files to '$PKGDIR'"
    inst -d "$PKGDIR/usr"
    cd "$PKGDIR"

    echo "$PKGDIR"

    # create directory structure
    # inst -d usr/sbin usr/bin usr/lib etc/hip usr/share/doc etc/init.d
    inst -d usr/sbin usr/bin etc/init.d etc/hip
    cd "$HIPL"
    
    echo "$HIPL"

    inst hipd/hipd $PKGDIR/usr/sbin/
    echo "** Copying init.d script to $PKGDIR"
    inst test/packaging/debian-init.d-hipd $PKGDIR/etc/init.d/hipd
    
    PKGNAME="${NAME}-$TMP-${TMPNAME}.${POSTFIX}"
    create_sub_package;
    
    TMP="firewall"
    DEBLIB="$NAME-lib"
    init_files;
    
    echo "** Making directory to '$PKGDIR'"
    inst -d "$PKGDIR/usr"
    cd "$PKGDIR"

    # inst -d usr/sbin
    inst -d usr/sbin usr/bin etc/init.d etc/hipfw
    cd "$HIPL"

    echo "** Copying firewall to $PKGDIR"
    inst firewall/hipfw $PKGDIR/usr/sbin/

    echo "** Copying init.d script to $PKGDIR"
    inst test/packaging/debian-init.d-hipfw $PKGDIR/etc/init.d/hipfw

    PKGNAME="${NAME}-$TMP-${TMPNAME}.${POSTFIX}"
    create_sub_package;

    TMP="dnsproxy"
    if [ $DEBARCH = "armel" ]; then 
	DEBLIB="python2.5"
    else
	DEBLIB=""
    fi
    init_files;
    
    echo "** Making directory to '$PKGDIR'"
    inst -d "$PKGDIR/usr"
    cd "$PKGDIR"

    # inst -d usr/sbin
    inst -d usr usr/sbin usr/bin etc/init.d
    cd "$HIPL"

    echo "** Copying dnsproxy to $PKGDIR"
    inst -d $PKGDIR/$PYEXECDIR
    inst -d $PKGDIR/$PYEXECDIR/hipdnsproxy
    inst -d $PKGDIR/$PYEXECDIR/hipdnskeyparse
    inst -d $PKGDIR/$PYEXECDIR/DNS

    inst tools/dnsproxy.py* $PKGDIR/$PYEXECDIR/hipdnsproxy
    inst tools/pyip6.py* $PKGDIR/$PYEXECDIR/hipdnsproxy
    inst tools/hosts.py* $PKGDIR/$PYEXECDIR/hipdnsproxy
    inst tools/util.py* $PKGDIR/$PYEXECDIR/hipdnsproxy
    inst tools/parse-key-3.py* $PKGDIR/$PYEXECDIR/hipdnsproxy

    inst tools/myasn.py* $PKGDIR/$PYEXECDIR/hipdnskeyparse
    inst tools/DNS/*py* $PKGDIR/$PYEXECDIR/DNS

    $SUDO tools/gen-python-starter.sh $PYEXECDIR/hipdnsproxy dnsproxy.py $PKGDIR/usr/sbin/hipdnsproxy
    $SUDO tools/gen-python-starter.sh $PYEXECDIR/hipdnskeyparse parse-key-3.py $PKGDIR/usr/sbin/hipdnskeyparse

    inst tools/nsupdate.pl $PKGDIR/usr/sbin

    echo "** Copying init.d script to $PKGDIR"
    inst test/packaging/debian-init.d-dnsproxy $PKGDIR/etc/init.d/hipdnsproxy

    PKGNAME="${NAME}-$TMP-${TMPNAME}.${POSTFIX}"
    create_sub_package;

    TMP="tools"
    #hipl-tools (depends on hipl-lib and hipl-daemon)
    DEBLIB="$NAME-lib, $NAME-daemon"
    init_files;

    echo "** Making directory to '$PKGDIR'"
    inst -d "$PKGDIR/usr"
    cd "$PKGDIR"

    inst -d usr/sbin usr/bin

    cd "$HIPL"

    inst tools/hipconf $PKGDIR/usr/sbin/

    echo "** Copying init.d script to $PKGDIR"
    inst test/packaging/debian-init.d-dnsproxy $PKGDIR/etc/init.d/hipdnsproxy

    PKGNAME="${NAME}-$TMP-${TMPNAME}.${POSTFIX}"
    create_sub_package;
   
    TMP="test"
    DEBLIB="$NAME-lib, $NAME-daemon"
    init_files;
    
    echo "** Making directory to '$PKGDIR'"
    inst -d "$PKGDIR/usr"
    cd "$PKGDIR"

    inst -d usr/bin usr/sbin
    cd "$HIPL"

    for suffix in -opp -hip -native -native-user-key;do
	inst test/conntest-client$suffix $PKGDIR/usr/bin/
    done

    for suffix in "" -native;do
	inst test/conntest-server$suffix $PKGDIR/usr/bin/
    done

    inst test/hipsetup $PKGDIR/usr/sbin/

    PKGNAME="${NAME}-$TMP-${TMPNAME}.${POSTFIX}"
    create_sub_package;

    TMP="agent"
    DEBLIB="$NAME-lib, $NAME-daemon"
    init_files;

    echo "** Making directory to '$PKGDIR'"
    #inst -d "$PKGDIR/usr"
    #cd "$PKGDIR"

    inst -d "$PKGDIR/usr"
    inst -d "$PKGDIR/usr/sbin"
    inst -d "$PKGDIR/usr/lib"
    inst -d "$PKGDIR/usr/share"
    inst -d "$PKGDIR/usr/share/hipl"
    inst -d "$PKGDIR/usr/share/hipl/libhipgui"
    inst -d "$PKGDIR/usr/share/menu"
    inst -d "$PKGDIR/usr/share/pixmaps"
    inst -d "$PKGDIR/usr/share/applications"
    inst -d "$PKGDIR/etc"
    inst -d "$PKGDIR/etc/xdg"
    inst -d "$PKGDIR/etc/xdg/autostart"

    #inst -d usr/sbin
    
    cd "$HIPL"

    echo "** Copying hipagent to '$PKGDIR'"
    inst agent/hipagent $PKGDIR/usr/sbin/

    copy -d libhipgui/hipmanager.png $PKGDIR/usr/share/pixmaps/hipmanager.png

    set +e

    PKGNAME="${NAME}-$TMP-${TMPNAME}.${POSTFIX}"
    create_sub_package;
  
    TMP="doc"
    DEBLIB=""
    init_files;

    inst -d "$PKGDIR/usr"
    cd "$PKGDIR"

    if [ $DEBARCH != "armel" ]; then

    	inst -d usr/share/doc
    	#cd "$HIPL"

    	echo "** Copying documentation to '$PKGDIR'"
    	cd "$HIPL/doc"
    	DOCDIR_PREFIX=$PKGDIR/usr/share/doc make -e install
    	set +e
    
    	PKGNAME="${NAME}-$TMP-${TMPNAME}.${POSTFIX}"
    	create_sub_package;
    fi

}


error_cleanup()
{
    if [ -n "$PKGDIR" -a -d "$PKGDIR" ];then
	echo "** Removing '$PKGDIR'"
	if ! remove -rf "$PKGDIR";then
	    echo "** Warning: Some error occurred while removing directory '$PKGDIR'"
	fi
    fi
}

create_sub_package()
{

    echo "** Creating the Debian package '$PKGNAME'"
    cd "$PKGROOT"
    if dpkg-deb -b "$PKGDIR" "$PKGNAME";then
	echo "** Successfully finished building the binary Debian package"
	echo "** The debian packages is located in $PKGROOT/$PKGNAME"
	echo "** The package can now be installed with dpkg -i $PKGROOT/$PKGNAME"
    else
	echo "** Error: unable to build package, exiting"
	error_cleanup
	exit 1
    fi

    remove -rf ${PKGDIR}
}

error_cleanup_src()
{
    if [ -n "$PKGDIR_SRC" -a -d "$PKGDIR_SRC" ];then
	echo "** Removing '$PKGDIR'"
	if ! rm -rf "$PKGDIR";then
	    echo "** Warning: Some error occurred while removing directory '$PKGDIR_SRC'"
	fi
    fi
}

die() {
    echo "$0: $@"
    exit 1
}

help() {
cat <<EOF
#usage: $0 [-b] | [-s] | [-a]
#b=binary, s=source, a=armel
usage: $0 [-b] | [-s]
b=binary, s=source
default: ${TYPE}
EOF
}


parse_args() {
    OPTIND=1
    while [ $# -ge  $OPTIND ]
      do
      getopts abchs N "$@"
      
      case $N in
	#    a) TYPE=binary
        #     	DEBIAN=armel/DEBIAN
	#	PKGNAME="${NAME}-${VERSION}-${RELEASE}-armel.deb" ;;

            b) TYPE=binary    
               	GIVEN=${GIVEN}+1 ;;

            s) TYPE=source ;;

            # XX FIXME!!!
	    c) TYPE=binary
	       GIVEN=${GIVEN}+1
	       CORPORATE=1 ;;

            h) help; exit 0 ;;

            *) help
               die "bad args" ;;
        esac
    done
}

######################## "Main" function #############################

parse_args $@

echo "** Creating the directory structure and files for building the"
echo "** binary Debian package containing HIPL user space software"
echo "**"
echo "** Building: Version $VERSION (release $RELEASE)"
echo "**"

echo "** Using directory '$HIPL' as the HIPL installation directory"
echo "** Package building root is '$PKGROOT'" 
echo "** Temporary Debian package root is '$PKGDIR'" 

echo "**"
echo "** NOTICE THAT PACKAGE BUILDING REQUIRES SUDO PRIVILEGES!!!"
echo "**"

if [ ! -d "$HIPL" ];then
  echo "** Error: '$HIPL' is not a directory, exiting"
  exit 1
fi

if [ $TYPE = "binary" ];then
# Binary Debian Package
# First compile all programs
    echo "** Compiling user space software"
    echo "**"

	if [ "$CORPORATE" ];then
		echo "** Must do make install for libhiptool to be able to make hipl"
		echo "** (note: only when compiling libhiptool as dynamically linked)"
	    echo "** Running make in $HIPL/libhiptool"
		cd "$HIPL/libhiptool"
		if ! make;then
			echo "** Error while running make in $HIPL/libhiptool, exiting"
			exit 1
		fi
		if ! $SUDO make install;then
			echo "** Error while running make install in $HIPL/libhiptool, exiting"
			exit 1
		fi
	fi

    # jk: do not re-configure as it messes up any configs we might need.
    cd "$HIPL"
    #echo "** Running make in $HIPL"
    #./autogen.sh
    #./configure --prefix=/usr
    #echo "** Running make in $HIPL"
    #if ! make clean all;then
    echo "** Running make in $HIPL"
    if ! make all;then
    	echo "** Error while running make in $HIPL, exiting"
    	exit 1
    fi
    echo "** Compilation was successful"
    echo "**"

	cd "$PKGROOT"
    if [ -d "$PKGDIR" ];then
	if ! remove -rf "$PKGDIR";then
	    echo "** Error: unable to remove directory '$PKGDIR', exiting"
	    exit 1
	fi
    fi
	cd "$PKGROOT"
    if [ -d "$PKGDIRGPL" ];then
	if ! remove -rf "$PKGDIRGPL";then
	    echo "** Error: unable to remove directory '$PKGDIRGPL', exiting"
	    exit 1
	fi
    fi

    if ! inst -d "$PKGDIR";then
	echo "** Error: unable to create directory '$PKGDIR', exiting"
	exit 1
    fi

    if ! inst -d "$PKGDIRGPL";then
	echo "** Error: unable to create directory '$PKGDIRGPL', exiting"
	exit 1
    fi

    cd "$PKGROOT"
    if ! copy_and_package_files;then
	echo "** Error: unable to copy files and create packages, exiting"
	exit 1
    fi

    cd "$PKGROOT"
    if [ "$CORPORATE" = 1 ];then
	if ! copy_files_gpl;then
	    echo "** Error: unable to copy GPL files, exiting"
	    exit 1
	fi
	
	cd "$PKGROOT"
	if dpkg-deb -b "$PKGDIRGPL" "$PKGNAMEGPL";then
	    echo "** Successfully finished building the binary GPL Debian package"
	else
	    echo "** Error!"
	    echo "** Error: Unable to build the binary GPL Debian package!"
	    echo "** Error!"
	    exit 1
	fi
    fi

    for i in $PKGROOT/*.deb
    do
      echo "------------------- $i ----------------------------"
      dpkg -c $i
    done

fi

if [ $TYPE = "source" ];then
# Debian SOURCE package

    if ! install -d "$PKGDIR_SRC";then
	echo "** Error: unable to create directory '$PKGDIR_SRC', exiting"
	exit 1
    fi

    cd "$HIPL"

    echo "** Running make dist in $HIPL"
    if ! make dist;then
	echo "** Error while running 'make dist' in $HIPL, exiting"
	exit 1
    fi
    echo "** Tarball was successfully created"
    echo "**"

    if ! copy_tarball;then
	echo "** Error: unable to copy tarball, exiting"
	error_cleanup_source
	exit 1
    fi

    echo "** Creating the Debian Source package of $PKGDIR"
    cd "${PKGDIR_SRC}"
    
    if dpkg-source -b "${NAME}${SUFFIX}";then

	remove -rf "${NAME}${SUFFIX}"

	dpkg-scansources . /dev/null | gzip -9c > Sources.gz

	echo "** Successfully finished building the source Debian package"
	echo "** The debian packages are located in" 
        echo "$PKGDIR_SRC"
	echo "** and they are named:"
	echo "${NAME}-${VERSION}.diff.gz"
	echo "${NAME}-${VERSION}.dsc"
 	echo "${NAME}-${VERSION}.orig.tar.gz"
    else
	echo "** Error: unable to build package, exiting"
	rm -rf "${PKGDIR_SRC}"
	exit 1
    fi

    $SUDO rmdir $PKGROOT/libhiptool-1.0-deb
fi

exit 0

