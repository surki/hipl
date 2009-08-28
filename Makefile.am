
AUTOMAKE_OPTIONS = foreign

# For "make dist"
EXTRA_DIST =  doc/COPYING doc/HACKING doc/HOWTO.xml doc/drafts doc/Makefile
EXTRA_DIST += doc/README doc/design_choices.bib test/configs patches
EXTRA_DIST += doc/base-exchange-relay.png doc/base-exchange-rvs.png
EXTRA_DIST += hipsock jip
EXTRA_DIST += test/packaging/create-package.sh
EXTRA_DIST += test/packaging/hipl-rpm.spec test/packaging/hipl-deb.spec 
EXTRA_DIST += test/packaging/debbuild
EXTRA_DIST += test/packaging/rh-init.d-hipd test/packaging/rh-init.d-hipfw test/packaging/rh-init.d-dnsproxy
EXTRA_DIST += test/packaging/debian-init.d-hipd test/packaging/debian-init.d-hipfw test/packaging/debian-init.d-dnsproxy
# The design choices doc is currently depracated
EXTRA_DIST += doc/design_choices.tex doc/hipl.tex doc/acronyms.tex
EXTRA_DIST += doc/design_choices_macros.tex doc/catalogue.tex doc/fig
EXTRA_DIST += libhipgui/hipmanager.png doc/HACKING
EXTRA_DIST += doc/doxygen.h doc/Doxyfile
EXTRA_DIST += hipext/hipext.xpi hipext/src/content/hipext.xul hipext/src/content/hipext.js hipext/src/chrome.manifest
EXTRA_DIST += hipext/src/install.rdf hipext/src/config_build.sh hipext/src/build.sh hipext/hipext.xpi
EXTRA_DIST += doc/docshot-agent-main-window.png doc/docshot-agent-tray-icon.png
EXTRA_DIST += i3-cfg-PL.xml
EXTRA_DIST += autogen.sh
EXTRA_DIST += @PJPROJECT_FILES@

# XX TODO: remove these when maemo building uses spec files
EXTRA_DIST += test/packaging/create-deb.sh
EXTRA_DIST += test/packaging/armel/DEBIAN-dnsproxy/control
EXTRA_DIST += test/packaging/armel/DEBIAN-dnsproxy/prerm
EXTRA_DIST += test/packaging/armel/DEBIAN-dnsproxy/rules
EXTRA_DIST += test/packaging/armel/DEBIAN-dnsproxy/changelog
EXTRA_DIST += test/packaging/armel/DEBIAN-dnsproxy/postinst
EXTRA_DIST += test/packaging/armel/DEBIAN-dnsproxy/control-src
EXTRA_DIST += test/packaging/armel/DEBIAN-dnsproxy/postrm
EXTRA_DIST += test/packaging/armel/DEBIAN-dnsproxy/copyright
EXTRA_DIST += test/packaging/armel/DEBIAN-dnsproxy/preinst
EXTRA_DIST += test/packaging/armel/DEBIAN-FW/control
EXTRA_DIST += test/packaging/armel/DEBIAN-FW/prerm
EXTRA_DIST += test/packaging/armel/DEBIAN-FW/rules
EXTRA_DIST += test/packaging/armel/DEBIAN-FW/changelog
EXTRA_DIST += test/packaging/armel/DEBIAN-FW/postinst
EXTRA_DIST += test/packaging/armel/DEBIAN-FW/control-src
EXTRA_DIST += test/packaging/armel/DEBIAN-FW/postrm
EXTRA_DIST += test/packaging/armel/DEBIAN-FW/copyright
EXTRA_DIST += test/packaging/armel/DEBIAN-FW/preinst
EXTRA_DIST += test/packaging/armel/DEBIAN-gconf/control
EXTRA_DIST += test/packaging/armel/DEBIAN-gconf/changelog
EXTRA_DIST += test/packaging/armel/DEBIAN-gconf/postinst
EXTRA_DIST += test/packaging/armel/DEBIAN-gconf/postrm
EXTRA_DIST += test/packaging/armel/DEBIAN-gconf/copyright
EXTRA_DIST += test/packaging/armel/DEBIAN/control
EXTRA_DIST += test/packaging/armel/DEBIAN/prerm
EXTRA_DIST += test/packaging/armel/DEBIAN/rules
EXTRA_DIST += test/packaging/armel/DEBIAN/changelog
EXTRA_DIST += test/packaging/armel/DEBIAN/postinst
EXTRA_DIST += test/packaging/armel/DEBIAN/control-src
EXTRA_DIST += test/packaging/armel/DEBIAN/postrm
EXTRA_DIST += test/packaging/armel/DEBIAN/copyright
EXTRA_DIST += test/packaging/armel/DEBIAN/preinst


CLEANFILES = pjproject/pjlib/lib/libpj-hipl.a \
             pjproject/pjnath/lib/libpjnath-hipl.a \
             pjproject/pjlib-util/lib/libpjlib-util-hipl.a \
             pjproject/pjlib/build/.pjlib-hipl.depend \
             pjproject/pjlib/build/.pjlib-test-hipl.depend \
             pjproject/pjnath/build/.pjturn-client-hipl.depend \
             pjproject/pjnath/build/.pjturn-srv-hipl.depend \
             pjproject/pjnath/build/.pjnath-test-hipl.depend \
             pjproject/pjnath/build/.pjnath-hipl.depend \
             pjproject/pjlib-util/build/.pjlib-util-test-hipl.depend \
             pjproject/pjlib-util/build/.pjlib-util-hipl.depend

# Note: pjproject and libinet6 has to be the first ones
#
SUBDIRS = pjproject libinet6 libhiptool libopphip libipsec libdht tools
if HIP_I3
SUBDIRS += i3
endif
SUBDIRS += hipd test firewall libhipgui agent hipfwmi

doxygen:
	cd doc && doxygen
rpm:
	test/packaging/create-package.sh rpm

olddeb:
        env PYEXECDIR=$(pyexecdir) test/packaging/create-deb.sh
        env PYEXECDIR=$(pyexecdir) test/packaging/create-deb.sh -s

deb:
	env PYEXECDIR=$(pyexecdir) test/packaging/create-package.sh deb

bin:
	env PYEXECDIR=$(pyexecdir) test/packaging/create-package.sh bin

increl:
	test/packaging/create-package.sh increl

syncrepo:
	test/packaging/create-package.sh syncrepo

dist-hook:
	rm -rf `find $(distdir) -name .arch-ids`

