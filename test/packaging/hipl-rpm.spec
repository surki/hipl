Name: hipl
Summary: HIP IPsec key management and mobility daemon.
# Note: Version and Release are read automatically from topdir release.version
URL: http://infrahip.hiit.fi/
Source: http://infrahip.hiit.fi/hipl/release/sources/%{version}/hipl-%{version}.tar.gz
Packager: miika@iki.fi
Vendor: InfraHIP
License: GPLv2
Group: System Environment/Kernel
#Requires: openssl gtk2 libxml2 glib2 iptables-devel
BuildRequires: gcc gcc-c++ openssl-devel gtk2-devel libxml2-devel glib2-devel iptables-devel xmlto libtool libcap-devel sqlite-devel autoconf automake xmlto rpm-build
ExclusiveOS: linux
BuildRoot: %{_tmppath}/%{name}-%{version}-root
Prefix: /usr

%description

Host Identity Protocol (HIP) provides cryptographic authentication to
between hosts and secure communications using IPsec. HIP protocol
extensions support also mobility and multihoming, and traversal of NATs.

HIP for Linux (HIPL) is an implementation of a HIP implementation that
consists of the key and mobility management daemon. It includes also
other related tools and test software.
%prep
%setup

#added by CentOS
%ifarch x86_64 ppc64 sparc64 ia64
%{__perl} -p -i -e 's,/usr/lib/libipq.a,/usr/lib64/libipq.a,g' firewall/Makefile.in
%endif

%{__perl} -p -i -e 's,/usr/share/pixmaps,\$(DESTDIR)/usr/share/pixmaps,g' libhipgui/Makefile.in
#end CentOS changes

# Note: in subsequent releases me may want to use --disable-debugging
# TBD: The pjproject needs to glued in better (convert it to automake).
#      That way we can get rid of the double configure (the second one is
#      currently required for bug id 524)
%build
./autogen.sh --prefix=/usr
%configure --prefix=/usr
make -C doc all

# Currently we are not going to install all includes and test software.
# As a consequence, we need to tell rpmbuild that we don't want to package
# everything and need the following two lines. In fact, the build fails
# without them). However, you might want to uncomment the lines temporarily
# before building the final release just to check that you have not discarded
# any essential files.
#
#%define _unpackaged_files_terminate_build 0
#%define _missing_doc_files_terminate_build 0
%define python_sitelib %(%{__python} -c 'from distutils import sysconfig; print sysconfig.get_python_lib()')


# Note: we are not distributing everything from test directory, just essentials

# create subpackage
# list of files with the name of subpackage

# XX TODO: copy descriptions from hipl-deb.spec and make sure rpm still builds

%package all
Summary: HIPL software bundle: HIP for Linux libraries, daemons and documentation
Group: System Environment/Kernel
Requires: hipl-lib hipl-firewall hipl-daemon hipl-agent hipl-tools hipl-test hipl-doc hipl-dnsproxy
%description all

%package lib
Summary: HIP for Linux libraries
Group: System Environment/Kernel
Requires: openssl libxml2 gtk2 iptables libcap sqlite
%description lib

%package daemon
 # miredo
Requires: hipl-lib iproute perl-Net-IP perl-Net-DNS perl-Socket6 perl-IO-Socket-INET6
Summary: HIP for Linux IPsec key management and mobility daemon
Group: System Environment/Kernel
%description daemon

%package tools
Requires: hipl-lib hipl-daemon
Summary: Command line tools to control hipd from command line
Group: System Environment/Kernel
%description tools

%package firewall
Requires: hipl-lib
Summary: HIPL multi-purpose firewall daemon. Public-key/HIT-based access control, Local Scope Identifier support, userspace BEET-mode IPsec (for kernels below < 2.6.27) and system-based opportunistic mode for HIP.
Group: System Environment/Kernel
%description firewall

%package test
Requires: hipl-lib hipl-daemon
Summary: netcat-like command line tools with built-in HIP support for developers 
Group: System Environment/Kernel
%description test

%package doc
Summary: documentation for HIP for Linux
Group: System Environment/Kernel
%description doc

%package dnsproxy
Requires: python hipl-lib
Summary: Name look-up proxy for HIP for Linux. Intercepts DNS look-ups and returns HIT or LSIs when corresponding entries are found in DNS, DHT or hosts files
Group: System Environment/Kernel
%description dnsproxy

%package agent
Requires: hipl-lib hipl-daemon
Summary: Graphical user interface for HIP for Linux. Provides user-friendly access control "buddy" lists for HIP.
Group: System Environment/Kernel
%description agent

%install
rm -rf %{buildroot}

#added by CentOS
install -d %{buildroot}%{prefix}/share/pixmaps
#end CentOS add

# XX FIXME: add more python stuff from tools directory

install -d %{buildroot}%{prefix}/bin
install -d %{buildroot}%{prefix}/sbin
install -d %{buildroot}%{prefix}/lib
install -d %{buildroot}/etc/rc.d/init.d
install -d %{buildroot}/doc
make DESTDIR=%{buildroot} install
install -m 700 test/packaging/rh-init.d-hipfw %{buildroot}/etc/rc.d/init.d/hipfw
install -m 700 test/packaging/rh-init.d-hipd %{buildroot}/etc/rc.d/init.d/hipd
install -m 700 test/packaging/rh-init.d-dnsproxy %{buildroot}/etc/rc.d/init.d/hipdnsproxy
install -m 644 doc/HOWTO.txt %{buildroot}/doc
install -d %{buildroot}%{python_sitelib}/DNS
install -t %{buildroot}%{python_sitelib}/DNS tools/DNS/*py*
install -d %{buildroot}%{python_sitelib}/hipdnsproxy
install -t %{buildroot}%{python_sitelib}/hipdnsproxy tools/dnsproxy.py*
install -t %{buildroot}%{python_sitelib}/hipdnsproxy tools/pyip6.py*
install -t %{buildroot}%{python_sitelib}/hipdnsproxy tools/hosts.py*
install -t %{buildroot}%{python_sitelib}/hipdnsproxy tools/util.py*
install -d %{buildroot}%{python_sitelib}/hipdnskeyparse
install -t %{buildroot}%{python_sitelib}/hipdnskeyparse tools/parse-key-3.py*
install -t %{buildroot}%{python_sitelib}/hipdnskeyparse tools/myasn.py*
# required in CentOS release 5.2
install -m 700 tools/hipdnskeyparse %{buildroot}%{prefix}/sbin/hipdnskeyparse
install -m 700 tools/hipdnsproxy %{buildroot}%{prefix}/sbin/hipdnsproxy

%post lib
/sbin/ldconfig 

%post daemon
if [ "$1" = "2" ]
then
	# upgrade
	/sbin/service hipd restart
else
	# first install
	/sbin/chkconfig --add hipd
	/sbin/chkconfig --level 2 hipd on
	/sbin/service hipd start
fi

%preun daemon
if [ "$1" = "0" ]
then
	# removing package completely
	/sbin/service hipd stop
	/sbin/chkconfig --del hipd
fi

%post dnsproxy
if [ "$1" = "2" ]
then
	# upgrade
	/sbin/service hipdnsproxy restart
else
	# first install
	/sbin/chkconfig --add hipdnsproxy
	/sbin/chkconfig --level 2 hipdnsproxy on
	/sbin/service hipdnsproxy start
fi

%preun dnsproxy
if [ "$1" = "0" ]
then
	# removing package completely
	/sbin/service hipdnsproxy stop
	/sbin/chkconfig --del hipdnsproxy
fi

%post firewall
if [ "$1" = "2" ]
then
	# upgrade
	/sbin/service hipfw restart
else
	# first install
	/sbin/chkconfig --add hipfw
	/sbin/chkconfig --level 2 hipfw on
	/sbin/service hipfw start
fi

%preun firewall
if [ "$1" = "0" ]
then
	# removing package completely
	/sbin/service hipfw stop
	/sbin/chkconfig --del hipfw
fi

%clean
rm -rf %{buildroot}

%files lib
%{_libdir}

%files daemon
%{prefix}/sbin/hipd
%{prefix}/bin/hipsetup
%config /etc/rc.d/init.d/hipd

%files agent
%{prefix}/sbin/hipagent

%files dnsproxy
%{prefix}/sbin/hipdnsproxy
%{prefix}/sbin/hipdnskeyparse
%{python_sitelib}/hipdnsproxy
%{python_sitelib}/hipdnskeyparse
%{python_sitelib}/DNS
%defattr(755,root,root)
%config /etc/rc.d/init.d/hipdnsproxy

%files tools
%{prefix}/sbin/hipconf
%{prefix}/sbin/nsupdate.pl
%defattr(755,root,root)

%files test
%{prefix}/bin/conntest-client-opp
%{prefix}/bin/conntest-client-hip
%{prefix}/bin/conntest-client-native
%{prefix}/bin/conntest-client-native-user-key
%{prefix}/bin/conntest-server
%{prefix}/bin/conntest-server-native

%files firewall
%{prefix}/sbin/hipfw
%config /etc/rc.d/init.d/hipfw

%files doc
%doc doc/HOWTO.txt doc/howto-html

%files all


%changelog
* Wed Dec 31 2008 Miika Komu <miika@iki.fi>
- Packaging improvements and lots of testing
* Wed Aug 20 2008 Miika Komu <miika@iki.fi>
- Dnsproxy separated into a separate package. Python packaging improvements.
* Mon Jul 21 2008 Miika Komu <miika@iki.fi>
- Rpmbuild fixes for Fedora 8 build
* Thu Jul 17 2008 Johnny Hughes <johnny@centos.org>
- added two perl searches and installed one directory in the spec file
- added libtool, libcap-devel and xmlto to BuildRequires 
* Thu May 29 2008 Juha Jylhakoski <juha.jylhakoski@hiit.fi>
- Split hipl.spec was split to different packages
* Tue May 9 2006 Miika Komu <miika@iki.fi>
- init.d script, buildroot
* Mon May 6 2006 Miika Komu <miika@iki.fi>
- Minor changes. Works, finally!
* Fri May 5 2006 Miika Komu <miika@iki.fi>
- Renamed to hipl.spec (original was from Mika) and modularized
* Tue Feb 14 2006 Miika Komu <miika@iki.fi>
- added changelog

