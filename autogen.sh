#!/bin/sh

### Functions ###

display_dependencies() {
    echo "The following packages are needed for building HIPL software bundle:"
    if test -e /etc/debian_version
	then
	echo "apt-get install automake autoconf libtool gcc g++ libgtk2.0-dev libssl-dev libxml2-dev xmlto doxygen iproute netcat6 iptables-dev libcap-dev libsqlite3-dev libuuid1 libnet-ip-perl libnet-dns-perl libsocket6-perl libio-socket-inet6-perl"
	echo "Optional: apt-get install miredo tla"
    elif test -e /etc/redhat-release
	then
	echo "yum install gcc gcc-c++ openssl-devel libxml2-devel autoconf automake libtool iproute gtk2-devel xmlto doxygen iptables-devel libcap-devel sqlite-devel rpm-build perl-Net-IP perl-Net-DNS perl-Socket6 perl-IO-Socket-INET6"
	echo "Optional: yum install uuid miredo tla"
	echo "If yum does not find a package, try searching 'rpm.pbone.net' or 'rpmfind.net' or install from sources"
    else
	echo -n "Unknown linux system:"
	cat /etc/lsb-release
	echo "You should install the following software:"
	echo "autoreconf, automake, autoconf, libtool, gcc, g++, xmlto, doxygen, iproute, netcat6, Socket6, IO::Socket::INET6, Net::IP and Net::DNS modules for perl"
	echo "And the following packages with their development headers:"
	echo "libgtk2.0, openssl, libxml2, iptables, libcap, libsqlite3"
	echo "Optionally you can install also uuid, miredo, tla"
    fi
}

display_kernel_info() {
    release=`uname -r`
    major=`echo $release|cut -d. -f 1`
    middle=`echo $release|cut -d. -f 2`
    minor=`echo $release|cut -d. -f 3`
    minor=`echo $minor|cut -d- -f 1` # e.g. 2.6.27-7-generic
    echo "HIPL kernel dependencies:"
    echo "Current kernel version is $release"
    if test $major -ge 2 && test $middle -ge 6 && test $minor -ge 27
	then
	echo "Your kernel version does not require patching"
    elif echo $release|grep -q hipl
	then
	echo "Seems like your current kernel does not require patching"
    else
	echo "You have to patch your kernel (see patches/kernel directory) or use userspace ipsec provided by hipfw"
    fi
    echo "(Note: if you want to use the optional native programming interface, you need to patch your kernel anyway, see patches/kernel directory)"
}

display_post_info() {
  echo "" && \
  echo "NOTE: The commands above only build the userspace software." && \
  display_kernel_info && \
  echo "NOTE: Run './configure --help' for more information"
  echo "NOTE: libjip and hipsock need to be compiled separately with make"
}

display_pre_info() {
    echo "Generating configure files... may take a while."
    echo "Configuring pjproject"
}

setup_pjproject() {
    cd pjproject && ./configure $@ || \
       (echo "Failed to configure pjproject" && display_dependencies && exit 1)
    make dep
    cd ..
    # Note: autogen options are also passed to HIPL configure.
    # See bug id 524)
   echo "Pjproject was configured successfully"
}

setup_hipl() {
    echo "Now configuring hipl with default configure options"
    autoreconf --install --force || \
	(echo "Missing libtool, automake, autoconf or autoreconf?" && exit 1)
    ./configure $@ || \
	(echo "Failed to configure hipl" && display_dependencies && exit 1)
    make
}

help() {
    echo "HIPL software dependencies:"
    display_dependencies
    display_kernel_info
    echo "When you have installed the software mentioned above, please run ./autogen.sh"
}

### Main program ###

if echo $1|grep -q help
then
    help
    exit
fi

display_pre_info
setup_pjproject $@

setup_hipl $@ && display_post_info
display_kernel_info
