# Customize it with the kernel version you are running
Version: 2.6.17.14

# Customize the sub-release (it will be used in the "EXTRAVERSION"
# variable of the main Makefile)
Release: hipl

# Customize here your config files location
%define KernelConfDir /usr/src/linux-%{version}
#-%{release}

Name: linux
Summary: The Linux Kernel
License: GPL
Group: System Environment/Kernel
Vendor: InfraHIP
URL: infrahip.hiit.fi
Source: linux-%{version}-%{release}.tar.bz2
BuildRoot: /var/tmp/%{name}-%{version}-%{release}-root
Provides: module-info, kernel = %{version}-%{release}
Provides: kernel-drm = 4.1.0, kernel-drm = 4.2.0

%define __spec_install_post /usr/lib/rpm/brp-compress || :
%define debug_package %{nil}

%description
Linux Kernel with BEET patches

%prep
%setup -n linux-%{version}-%{release}
%build
[ -d $RPM_BUILD_ROOT ] && rm -fr $RPM_BUILD_ROOT
cp -f %{KernelConfDir}/.config .config
make clean
# For 2.4 make EXTRAVERSION=<blabla> does not works correctly
# (it does not update version.h) so we modify the Makefile :-(
perl -p -i -e 's/^EXTRAVERSION.*/EXTRAVERSION=-%{release}/' Makefile

make oldconfig
make -j2 bzImage
make -j2 modules
# Create directories
mkdir -p $RPM_BUILD_ROOT/boot $RPM_BUILD_ROOT/lib
mkdir -p $RPM_BUILD_ROOT/lib/modules/%{version}-%{release}
mkdir -p $RPM_BUILD_ROOT/lib/modules/%{version}-%{release}smp
# Install kernel + modules
cp arch/i386/boot/bzImage $RPM_BUILD_ROOT/boot/vmlinuz-%{version}-%{release}
cp System.map $RPM_BUILD_ROOT/boot/System.map-%{version}-%{release}
cp .config $RPM_BUILD_ROOT/boot/config-%{version}-%{release}
make INSTALL_MOD_PATH=$RPM_BUILD_ROOT modules_install

# Building kernel with SMP support
cp -f %{KernelConfDir}/.config_smp .config

# For 2.4 make EXTRAVERSION=<blabla> does not works correctly
# (it does not update version.h) so we modify the Makefile :-(
perl -p -i -e 's/^EXTRAVERSION.*/EXTRAVERSION=-%{release}smp/' Makefile

make oldconfig

make -j2 bzImage
make -j2 modules

# Install SMP kernel + modules
cp arch/i386/boot/bzImage $RPM_BUILD_ROOT/boot/vmlinuz-%{version}-%{release}smp
cp System.map $RPM_BUILD_ROOT/boot/System.map-%{version}-%{release}smp
cp .config $RPM_BUILD_ROOT/boot/config-%{version}-%{release}smp
make INSTALL_MOD_PATH=$RPM_BUILD_ROOT modules_install

%install
%files
%defattr (-, root, root)
%dir /lib/modules
/lib/modules/%{version}-%{release}
/boot/vmlinuz-%{version}-%{release}
/boot/System.map-%{version}-%{release}
/boot/config-%{version}-%{release}

 

 

####################################################################

### SMP !

####################################################################

%package smp

Summary: Kernel SMP with beet patches

Group: System Environment/Kernel

Provides: module-info, kernel = %{version}-%{release}

Provides: kernel-drm = 4.1.0, kernel-drm = 4.2.0

 

%description smp

Linux Kernel; version recompiled by InfraHIP / Miika Komu

Dual SMP version.

 

%files smp

%defattr (-, root, root)

%dir /lib/modules

/lib/modules/%{version}-%{release}smp

/boot/vmlinuz-%{version}-%{release}smp

/boot/System.map-%{version}-%{release}smp

/boot/config-%{version}-%{release}smp

 
