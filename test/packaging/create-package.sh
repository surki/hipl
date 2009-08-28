#!/bin/sh -xv

VERSION=
NAME=hipl
PKGROOT=$PWD
PKGEXE=$PKGROOT/test/packaging
PKG_WEB_DIR=
PKG_SERVER_DIR=
DEBDIR=/usr/src/debian
RPMDIR=/usr/src/redhat
SUBDEBDIRS="BUILD DEBS SOURCES SPECS SDEBS"
SUBRPMDIRS="BUILD RPMS SOURCES SPECS SRPMS"
SUDO=sudo
ARCH=
DISTRO_RELEASE=
DISTRO=
DISTROBASE=
DISTRO_PKG_SUFFIX=
REPO_SERVER=hipl.infrahip.net
REPO_BASE=/var/www/packages/html
BIN_FORMAT=
TARBALL=
RSYNC_OPTS=-uvr
REPO_USER=hipl
REPO_GROUP=hipl
SPECFILE_DIR=`mktemp -d`
SPECFILE=$SPECFILE_DIR/hipl.spec 
RELEASE_VERSION_FILE=$PKGROOT/release.version

inc_release_number()
{
    TMPFILE=`mktemp`
    TLA="tla"
    if test -x '/usr/bin/baz'
    then
	TLA="baz"
    fi
    awk \
    '{ \
        if ($1 == "Release:") { \
            print $1 " " ($2 + 1) \
        } else {                  \
            print              \
        } \
    }' < $RELEASE_VERSION_FILE >$TMPFILE
    mv $TMPFILE $RELEASE_VERSION_FILE
    echo "Now type:"
    echo "$TLA replay"
    echo "$TLA commit -s 'Increased release version number'"
}

die()
{
    echo $@
    exit 1
}

build_maemo_deb()
{
    env PYEXECDIR=$(PYEXECDIR) $PKGEXE/create-deb.sh
    env PYEXECDIR=$(PYEXECDIR) $PKGEXE/create-deb.sh -s
}

build_rpm()
{
    test -e ~/.rpmmacros && echo "Warning: ~/.rpmmacros found, could be a problem"
    if test -e ~/rpmbuild
    then
	echo "Warning: ~/rpmbuild found, could be a problem"
	echo "It should be a link to /usr/src/redhat"
    fi

    for SUBDIR in $SUBRPMDIRS
    do
	if test ! -d $RPMDIR/$SUBDIR
	then
	    $SUDO mkdir -p $RPMDIR/$SUBDIR
	fi
    done

    # The RPMs can be found from /usr/src/redhat/ SRPMS and RPMS
    $SUDO mv -f $TARBALL /usr/src/redhat/SOURCES
    $SUDO rpmbuild -ba $SPECFILE
}

mkindex_rpm()
{
    if test ! -d $PKG_INDEX
    then
	mkdir $PKG_INDEX
    fi
    #$SUDO createrepo --update --outputdir=$PKG_INDEX_DIR $PKG_DIR
    $SUDO createrepo --outputdir=$PKG_INDEX_DIR $PKG_DIR
}

mkindex_deb()
{
    ORIG=$PWD
    cd $PKG_DIR
    WD=`echo $PKG_WEB_DIR|sed 's/\//\\\\\//g'`
    #dpkg-scanpackages --multiversion . |
    dpkg-scanpackages . | \
	sed "s/Filename: \./Filename: $WD/" | \
	gzip -9c > $PKG_INDEX
    cd $ORIG
}

syncrepo()
{
    # We are reusing /usr/src/something to store multiversions of binaries
    # and we have to have download priviledges there for rsync.
    $SUDO chown $USER -R $PKG_DIR

    # create repo dir if it does not exist
    ssh ${REPO_USER}@${REPO_SERVER} mkdir -p $PKG_SERVER_DIR
    # (over)write package to the repository
    #rsync $RSYNC_OPTS $PKG_DIR/${NAME}-*${VERSION}*.${DISTRO_PKG_SUFFIX} ${REPO_USER}@${REPO_SERVER}:$PKG_SERVER_DIR/
    # fetch all versions of packages to build complete repo index
    #rsync $RSYNC_OPTS ${REPO_USER}@${REPO_SERVER}:$PKG_SERVER_DIR/ $PKG_DIR/

    # build index of all packages
    if test x"$DISTROBASE" = x"debian"
    then
	mkindex_deb
    elif test x"$DISTROBASE" = x"redhat"
    then
	mkindex_rpm
    else
	die "Unhandled distro $DISTROBASE"
    fi

    # Delete old packages from the repo
    ssh  ${REPO_USER}@${REPO_SERVER} "rm -f ${PKG_SERVER_DIR}/*.${DISTRO_PKG_SUFFIX}"

    # Copy all packages and repo index to the repository
    rsync $RSYNC_OPTS $PKG_DIR/${NAME}-*${VERSION}*.${DISTRO_PKG_SUFFIX} ${PKG_INDEX} ${REPO_USER}@${REPO_SERVER}:${PKG_SERVER_DIR}/

    # Restore file priviledges on /usr/src/somewhere
    $SUDO chown root -R $PKG_DIR
}

build_deb()
{
    if dpkg --print-architecture|grep -q armel
    then
	build_maemo_deb
	exit 0
    fi

    test -e ~/.debmacros && echo "Warning: ~/.debmacros found, could be a problem"
    if test -e ~/debbuild
    then
	echo "Warning: ~/debbuild found, could be a problem"
	echo "It should be a link to /usr/src/debian"
    fi

    if test ! -x /usr/bin/pax
    then
	die "apt-get install pax"
    fi

    for SUBDIR in $SUBDEBDIRS
    do
	if test ! -d $DEBDIR/$SUBDIR
	then
	    $SUDO mkdir -p $DEBDIR/$SUBDIR
	fi
    done

    $SUDO cp $SPECFILE $DEBDIR/SPECS

    $SUDO mv -f $TARBALL /usr/src/debian/SOURCES
    # http://www.deepnet.cx/debbuild/
    $SUDO $PKGEXE/debbuild -ba $SPECFILE
}

############### Main program #####################

set -e

cp $RELEASE_VERSION_FILE $SPECFILE

# Set architecture, distro and repo details
if test -r /etc/debian_version
then
    DISTROBASE=debian
    ARCH=`dpkg --print-architecture`
    PKG_DIR=$DEBDIR/DEBS/$ARCH 
    DISTRO_RELEASE=`lsb_release -c|cut -f2`
    DISTRO=`lsb_release -d|cut -f2|tr '[:upper:]' '[:lower:]'|cut -d" " -f1`
    PKG_WEB_DIR=dists/$DISTRO_RELEASE/main/binary-${ARCH}
    PKG_SERVER_DIR=$REPO_BASE/$DISTRO/$PKG_WEB_DIR
    cat $PKGEXE/hipl-deb.spec >> $SPECFILE
    VERSION=`grep Version: $SPECFILE|cut -d" " -f2`
    DISTRO_PKG_SUFFIX=deb
    PKG_INDEX_NAME=Packages.gz
    PKG_INDEX_DIR=$PKGEXE
    PKG_INDEX=$PKG_INDEX_DIR/$PKG_INDEX_NAME
elif test -r /etc/redhat-release
then
    DISTROBASE=redhat
    ARCH=`uname -i`
    PKG_DIR=$RPMDIR/RPMS/$ARCH
    DISTRO_RELEASE=`lsb_release -r|cut -f2`
    DISTRO=`lsb_release -d|cut -f2|tr '[:upper:]' '[:lower:]'|cut -d" " -f1`
    PKG_WEB_DIR=fedora/base/$DISTRO_RELEASE/$ARCH
    PKG_SERVER_DIR=$REPO_BASE/$PKG_WEB_DIR
    cat $PKGEXE/hipl-rpm.spec >> $SPECFILE
    VERSION=`grep Version: $SPECFILE|cut -d" " -f2`
    DISTRO_PKG_SUFFIX=rpm
    PKG_INDEX_NAME=repodata
    PKG_INDEX_DIR=$PKGEXE
    PKG_INDEX=$PKG_INDEX_DIR/$PKG_INDEX_NAME
else
    die "Unknown architecture"
fi

TARBALL=$PKGROOT/hipl-${VERSION}.tar.gz

# Determine action
if test x"$1" = x"syncrepo"
then
    syncrepo
    exit
elif test x"$1" = x"increl"
then
    inc_release_number
    exit
elif test x"$1" = x"bin"
then
    if test x"$DISTROBASE" = x"redhat"
    then
	BIN_FORMAT=rpm
    elif test x"$DISTROBASE" = x"debian"
    then
	BIN_FORMAT=deb
    else
	die "Unknown distro"
    fi
fi
echo "Architecture: $ARCH"

echo <<EOF
** Creating the directory structure and files for building the
** source package needed for RPM package containing HIPL
** user space software
**
** Version $VERSION
**
EOF

make dist
rm -rf ${NAME}-${VERSION}
tar xzf ${NAME}-main.tar.gz
#find ${NAME}-main -name '.arch*' | xargs rm -rf
mv -v ${NAME}-main ${NAME}-${VERSION}
tar czf $TARBALL ${NAME}-${VERSION}
#mv $PKGROOT/${NAME}-main.tar.gz $TARBALL
ls -ld $TARBALL

cat <<EOF

#############################################
# Assuming that you are in /etc/sudoers!!!! #
#############################################

EOF

echo "*** Cleaning up binaries from ${PKG_DIR} ***"
$SUDO rm -f ${PKG_DIR}/*.${BIN_FORMAT}

if test x"$1" = x"rpm" || test x"$BIN_FORMAT" = x"rpm"
then
    build_rpm
elif test x"$1" = x"deb" || test x"$BIN_FORMAT" = x"deb"
then
    build_deb
else
    die "*** Unknown platform, aborting ***"
fi

