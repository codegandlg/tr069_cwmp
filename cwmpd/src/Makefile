# Makefile.in generated by automake 1.13.4 from Makefile.am.
# cwmpd/src/Makefile.  Generated from Makefile.in by configure.

# Copyright (C) 1994-2013 Free Software Foundation, Inc.

# This Makefile.in is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY, to the extent permitted by law; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.




am__is_gnu_make = test -n '$(MAKEFILE_LIST)' && test -n '$(MAKELEVEL)'
am__make_running_with_option = \
  case $${target_option-} in \
      ?) ;; \
      *) echo "am__make_running_with_option: internal error: invalid" \
              "target option '$${target_option-}' specified" >&2; \
         exit 1;; \
  esac; \
  has_opt=no; \
  sane_makeflags=$$MAKEFLAGS; \
  if $(am__is_gnu_make); then \
    sane_makeflags=$$MFLAGS; \
  else \
    case $$MAKEFLAGS in \
      *\\[\ \	]*) \
        bs=\\; \
        sane_makeflags=`printf '%s\n' "$$MAKEFLAGS" \
          | sed "s/$$bs$$bs[$$bs $$bs	]*//g"`;; \
    esac; \
  fi; \
  skip_next=no; \
  strip_trailopt () \
  { \
    flg=`printf '%s\n' "$$flg" | sed "s/$$1.*$$//"`; \
  }; \
  for flg in $$sane_makeflags; do \
    test $$skip_next = yes && { skip_next=no; continue; }; \
    case $$flg in \
      *=*|--*) continue;; \
        -*I) strip_trailopt 'I'; skip_next=yes;; \
      -*I?*) strip_trailopt 'I';; \
        -*O) strip_trailopt 'O'; skip_next=yes;; \
      -*O?*) strip_trailopt 'O';; \
        -*l) strip_trailopt 'l'; skip_next=yes;; \
      -*l?*) strip_trailopt 'l';; \
      -[dEDm]) skip_next=yes;; \
      -[JT]) skip_next=yes;; \
    esac; \
    case $$flg in \
      *$$target_option*) has_opt=yes; break;; \
    esac; \
  done; \
  test $$has_opt = yes
am__make_dryrun = (target_option=n; $(am__make_running_with_option))
am__make_keepgoing = (target_option=k; $(am__make_running_with_option))
pkgdatadir = $(datadir)/library
pkgincludedir = $(includedir)/library
pkglibdir = $(libdir)/library
pkglibexecdir = $(libexecdir)/library
am__cd = CDPATH="$${ZSH_VERSION+.}$(PATH_SEPARATOR)" && cd
install_sh_DATA = $(install_sh) -c -m 644
install_sh_PROGRAM = $(install_sh) -c
install_sh_SCRIPT = $(install_sh) -c
INSTALL_HEADER = $(INSTALL_DATA)
transform = $(program_transform_name)
NORMAL_INSTALL = :
PRE_INSTALL = :
POST_INSTALL = :
NORMAL_UNINSTALL = :
PRE_UNINSTALL = :
POST_UNINSTALL = :
build_triplet = i686-pc-linux-gnu
host_triplet = mipsel-unknown-linux-gnu
bin_PROGRAMS = cwmpd$(EXEEXT)
subdir = cwmpd/src
DIST_COMMON = $(srcdir)/Makefile.in $(srcdir)/Makefile.am \
	$(top_srcdir)/build/mkinstalldirs $(top_srcdir)/build/depcomp
ACLOCAL_M4 = $(top_srcdir)/aclocal.m4
am__aclocal_m4_deps = $(top_srcdir)/configure.ac
am__configure_deps = $(am__aclocal_m4_deps) $(CONFIGURE_DEPENDENCIES) \
	$(ACLOCAL_M4)
mkinstalldirs = $(SHELL) $(top_srcdir)/build/mkinstalldirs
CONFIG_HEADER = $(top_builddir)/config.h
CONFIG_CLEAN_FILES =
CONFIG_CLEAN_VPATH_FILES =
am__installdirs = "$(DESTDIR)$(bindir)"
PROGRAMS = $(bin_PROGRAMS)
am_cwmpd_OBJECTS = cwmpd-conf.$(OBJEXT) cwmpd-cwmpd.$(OBJEXT) \
	cwmpd-httpd.$(OBJEXT) cwmpd-process.$(OBJEXT) \
	cwmpd-thread.$(OBJEXT) cwmpd-agent.$(OBJEXT) \
	cwmpd-data_model.$(OBJEXT)
cwmpd_OBJECTS = $(am_cwmpd_OBJECTS)
cwmpd_DEPENDENCIES =
AM_V_lt = $(am__v_lt_$(V))
am__v_lt_ = $(am__v_lt_$(AM_DEFAULT_VERBOSITY))
am__v_lt_0 = --silent
am__v_lt_1 = 
cwmpd_LINK = $(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
	$(LIBTOOLFLAGS) --mode=link $(CCLD) $(AM_CFLAGS) $(CFLAGS) \
	$(cwmpd_LDFLAGS) $(LDFLAGS) -o $@
AM_V_P = $(am__v_P_$(V))
am__v_P_ = $(am__v_P_$(AM_DEFAULT_VERBOSITY))
am__v_P_0 = false
am__v_P_1 = :
AM_V_GEN = $(am__v_GEN_$(V))
am__v_GEN_ = $(am__v_GEN_$(AM_DEFAULT_VERBOSITY))
am__v_GEN_0 = @echo "  GEN     " $@;
am__v_GEN_1 = 
AM_V_at = $(am__v_at_$(V))
am__v_at_ = $(am__v_at_$(AM_DEFAULT_VERBOSITY))
am__v_at_0 = @
am__v_at_1 = 
DEFAULT_INCLUDES = -I. -I$(top_builddir)
depcomp = $(SHELL) $(top_srcdir)/build/depcomp
am__depfiles_maybe = depfiles
am__mv = mv -f
COMPILE = $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
	$(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS)
LTCOMPILE = $(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
	$(LIBTOOLFLAGS) --mode=compile $(CC) $(DEFS) \
	$(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) \
	$(AM_CFLAGS) $(CFLAGS)
AM_V_CC = $(am__v_CC_$(V))
am__v_CC_ = $(am__v_CC_$(AM_DEFAULT_VERBOSITY))
am__v_CC_0 = @echo "  CC      " $@;
am__v_CC_1 = 
CCLD = $(CC)
LINK = $(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
	$(LIBTOOLFLAGS) --mode=link $(CCLD) $(AM_CFLAGS) $(CFLAGS) \
	$(AM_LDFLAGS) $(LDFLAGS) -o $@
AM_V_CCLD = $(am__v_CCLD_$(V))
am__v_CCLD_ = $(am__v_CCLD_$(AM_DEFAULT_VERBOSITY))
am__v_CCLD_0 = @echo "  CCLD    " $@;
am__v_CCLD_1 = 
SOURCES = $(cwmpd_SOURCES)
DIST_SOURCES = $(cwmpd_SOURCES)
am__can_run_installinfo = \
  case $$AM_UPDATE_INFO_DIR in \
    n|no|NO) false;; \
    *) (install-info --version) >/dev/null 2>&1;; \
  esac
am__tagged_files = $(HEADERS) $(SOURCES) $(TAGS_FILES) $(LISP)
# Read a list of newline-separated strings from the standard input,
# and print each of them once, without duplicates.  Input order is
# *not* preserved.
am__uniquify_input = $(AWK) '\
  BEGIN { nonempty = 0; } \
  { items[$$0] = 1; nonempty = 1; } \
  END { if (nonempty) { for (i in items) print i; }; } \
'
# Make sure the list of sources is unique.  This is necessary because,
# e.g., the same source file might be shared among _SOURCES variables
# for different programs/libraries.
am__define_uniq_tagged_files = \
  list='$(am__tagged_files)'; \
  unique=`for i in $$list; do \
    if test -f "$$i"; then echo $$i; else echo $(srcdir)/$$i; fi; \
  done | $(am__uniquify_input)`
ETAGS = etags
CTAGS = ctags
DISTFILES = $(DIST_COMMON) $(DIST_SOURCES) $(TEXINFOS) $(EXTRA_DIST)
ACLOCAL = aclocal-1.13
ALLOCA = 
AMTAR = $${TAR-tar}
AM_DEFAULT_VERBOSITY = 1
AR = mipsel-linux-ar
AUTOCONF = autoconf
AUTOHEADER = autoheader
AUTOMAKE = automake-1.13
AWK = mawk
BUILD_CPU = i686
BUILD_OS = linux-gnu
BUILD_VENDOR = pc
CC = mipsel-linux-gcc
CCDEPMODE = depmode=gcc3
CFLAGS = -Wall -g 
CPP = mipsel-linux-gcc -E
CPPFLAGS = -D_GNU_SOURCE -Wall -g
CXX = mipsel-linux-g++
CXXCPP = mipsel-linux-g++ -E
CXXDEPMODE = depmode=gcc3
CXXFLAGS = -g -O2
CYGPATH_W = echo
DEFS = -DHAVE_CONFIG_H
DEPDIR = .deps
DLLTOOL = false
DSYMUTIL = 
DUMPBIN = 
ECHO_C = 
ECHO_N = -n
ECHO_T = 
EGREP = /bin/grep -E
EXEEXT = 
FGREP = /bin/grep -F
GREP = /bin/grep
HOST_CPU = mipsel
HOST_OS = linux-gnu
HOST_VENDOR = unknown
INSTALL = /usr/bin/install -c
INSTALL_DATA = ${INSTALL} -m 644
INSTALL_PROGRAM = ${INSTALL}
INSTALL_SCRIPT = ${INSTALL}
INSTALL_STRIP_PROGRAM = $(install_sh) -c -s
LD = /opt/buildroot-gdb/mipsel-linux-uclibc/bin/ld
LDFLAGS = 
LIBOBJS =  ${LIBOBJDIR}lstat$U.o ${LIBOBJDIR}stat$U.o
LIBS = 
LIBTOOL = $(SHELL) $(top_builddir)/libtool
LIPO = 
LN_S = ln -s
LTLIBOBJS =  ${LIBOBJDIR}lstat$U.lo ${LIBOBJDIR}stat$U.lo
LT_SYS_LIBRARY_PATH = 
MAKEINFO = makeinfo
MANIFEST_TOOL = :
MKDIR_P = /bin/mkdir -p
NM = /opt/buildroot-gdb/bin/mipsel-linux-nm -B
NMEDIT = 
OBJDUMP = mipsel-linux-objdump
OBJEXT = o
OPENSSL_DIR = no
OTOOL = 
OTOOL64 = 
PACKAGE = library
PACKAGE_BUGREPORT = support@itibia.com
PACKAGE_NAME = library
PACKAGE_STRING = library 1.0
PACKAGE_TARNAME = library
PACKAGE_URL = 
PACKAGE_VERSION = 1.0
PATH_SEPARATOR = :
RANLIB = mipsel-linux-ranlib
SED = /bin/sed
SET_MAKE = 
SHELL = /bin/sh
STRIP = mipsel-linux-strip
VERSION = 1.0
abs_builddir = /work/haopeng/trunk/user/cwmp/cwmpd/src
abs_srcdir = /work/haopeng/trunk/user/cwmp/cwmpd/src
abs_top_builddir = /work/haopeng/trunk/user/cwmp
abs_top_srcdir = /work/haopeng/trunk/user/cwmp
ac_ct_AR = 
ac_ct_CC = 
ac_ct_CXX = 
ac_ct_DUMPBIN = 
am__include = include
am__leading_dot = .
am__quote = 
am__tar = $${TAR-tar} chof - "$$tardir"
am__untar = $${TAR-tar} xf -
bindir = ${exec_prefix}/bin
build = i686-pc-linux-gnu
build_alias = i686-linux
build_cpu = i686
build_os = linux-gnu
build_vendor = pc
builddir = .
datadir = ${datarootdir}
datarootdir = ${prefix}/share
docdir = ${datarootdir}/doc/${PACKAGE_TARNAME}
dvidir = ${docdir}
exec_prefix = ${prefix}
host = mipsel-unknown-linux-gnu
host_alias = mipsel-linux
host_cpu = mipsel
host_os = linux-gnu
host_vendor = unknown
htmldir = ${docdir}
includedir = ${prefix}/include
infodir = ${datarootdir}/info
install_sh = ${SHELL} /work/haopeng/trunk/user/cwmp/build/install-sh
libdir = ${exec_prefix}/lib
libexecdir = ${exec_prefix}/libexec
localedir = ${datarootdir}/locale
localstatedir = ${prefix}/var
mandir = ${datarootdir}/man
mkdir_p = $(MKDIR_P)
oldincludedir = /usr/include
pdfdir = ${docdir}
prefix = /usr/local
program_transform_name = s,x,x,
psdir = ${docdir}
sbindir = ${exec_prefix}/sbin
sharedstatedir = ${prefix}/com
srcdir = .
sysconfdir = ${prefix}/etc
target_alias = 
top_build_prefix = ../../
top_builddir = ../..
top_srcdir = ../..
cwmpd_SOURCES = conf.c  cwmpd.c  httpd.c  process.c  thread.c agent.c modules/data_model.c 
AM_CPPFLAGS = -DUSE_CWMP_MEMORY_POOL -I$(top_srcdir)/include  -I$(top_srcdir)/cwmpd/include -I$(top_srcdir)/libpool/include  -I$(top_srcdir)/libxmlet/include -I$(top_srcdir)/libcwmp/include  -I $(top_srcdir)/../../lib/libnvram
cwmpd_LDADD = -L$(top_srcdir)/libpool/src -L$(top_srcdir)/libxmlet/src -L$(top_srcdir)/libcwmp/src -L$(top_srcdir)/../../user/nvram -lpool -lxmlet  -lcwmp  -lpthread -lnvram
cwmpd_CPPFLAGS = $(AM_CPPFLAGS) 
cwmpd_LDFLAGS = -D_GNU_SOURCE -DUSE_CWMP_MEMORY_POOL  
all: all-am

.SUFFIXES:
.SUFFIXES: .c .lo .o .obj
$(srcdir)/Makefile.in:  $(srcdir)/Makefile.am  $(am__configure_deps)
	@for dep in $?; do \
	  case '$(am__configure_deps)' in \
	    *$$dep*) \
	      ( cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh ) \
	        && { if test -f $@; then exit 0; else break; fi; }; \
	      exit 1;; \
	  esac; \
	done; \
	echo ' cd $(top_srcdir) && $(AUTOMAKE) --foreign cwmpd/src/Makefile'; \
	$(am__cd) $(top_srcdir) && \
	  $(AUTOMAKE) --foreign cwmpd/src/Makefile
.PRECIOUS: Makefile
Makefile: $(srcdir)/Makefile.in $(top_builddir)/config.status
	@case '$?' in \
	  *config.status*) \
	    cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh;; \
	  *) \
	    echo ' cd $(top_builddir) && $(SHELL) ./config.status $(subdir)/$@ $(am__depfiles_maybe)'; \
	    cd $(top_builddir) && $(SHELL) ./config.status $(subdir)/$@ $(am__depfiles_maybe);; \
	esac;

$(top_builddir)/config.status: $(top_srcdir)/configure $(CONFIG_STATUS_DEPENDENCIES)
	cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh

$(top_srcdir)/configure:  $(am__configure_deps)
	cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh
$(ACLOCAL_M4):  $(am__aclocal_m4_deps)
	cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh
$(am__aclocal_m4_deps):
install-binPROGRAMS: $(bin_PROGRAMS)
	@$(NORMAL_INSTALL)
	@list='$(bin_PROGRAMS)'; test -n "$(bindir)" || list=; \
	if test -n "$$list"; then \
	  echo " $(MKDIR_P) '$(DESTDIR)$(bindir)'"; \
	  $(MKDIR_P) "$(DESTDIR)$(bindir)" || exit 1; \
	fi; \
	for p in $$list; do echo "$$p $$p"; done | \
	sed 's/$(EXEEXT)$$//' | \
	while read p p1; do if test -f $$p \
	 || test -f $$p1 \
	  ; then echo "$$p"; echo "$$p"; else :; fi; \
	done | \
	sed -e 'p;s,.*/,,;n;h' \
	    -e 's|.*|.|' \
	    -e 'p;x;s,.*/,,;s/$(EXEEXT)$$//;$(transform);s/$$/$(EXEEXT)/' | \
	sed 'N;N;N;s,\n, ,g' | \
	$(AWK) 'BEGIN { files["."] = ""; dirs["."] = 1 } \
	  { d=$$3; if (dirs[d] != 1) { print "d", d; dirs[d] = 1 } \
	    if ($$2 == $$4) files[d] = files[d] " " $$1; \
	    else { print "f", $$3 "/" $$4, $$1; } } \
	  END { for (d in files) print "f", d, files[d] }' | \
	while read type dir files; do \
	    if test "$$dir" = .; then dir=; else dir=/$$dir; fi; \
	    test -z "$$files" || { \
	    echo " $(INSTALL_PROGRAM_ENV) $(LIBTOOL) $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=install $(INSTALL_PROGRAM) $$files '$(DESTDIR)$(bindir)$$dir'"; \
	    $(INSTALL_PROGRAM_ENV) $(LIBTOOL) $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=install $(INSTALL_PROGRAM) $$files "$(DESTDIR)$(bindir)$$dir" || exit $$?; \
	    } \
	; done

uninstall-binPROGRAMS:
	@$(NORMAL_UNINSTALL)
	@list='$(bin_PROGRAMS)'; test -n "$(bindir)" || list=; \
	files=`for p in $$list; do echo "$$p"; done | \
	  sed -e 'h;s,^.*/,,;s/$(EXEEXT)$$//;$(transform)' \
	      -e 's/$$/$(EXEEXT)/' \
	`; \
	test -n "$$list" || exit 0; \
	echo " ( cd '$(DESTDIR)$(bindir)' && rm -f" $$files ")"; \
	cd "$(DESTDIR)$(bindir)" && rm -f $$files

clean-binPROGRAMS:
	@list='$(bin_PROGRAMS)'; test -n "$$list" || exit 0; \
	echo " rm -f" $$list; \
	rm -f $$list || exit $$?; \
	test -n "$(EXEEXT)" || exit 0; \
	list=`for p in $$list; do echo "$$p"; done | sed 's/$(EXEEXT)$$//'`; \
	echo " rm -f" $$list; \
	rm -f $$list

cwmpd$(EXEEXT): $(cwmpd_OBJECTS) $(cwmpd_DEPENDENCIES) $(EXTRA_cwmpd_DEPENDENCIES) 
	@rm -f cwmpd$(EXEEXT)
	$(AM_V_CCLD)$(cwmpd_LINK) $(cwmpd_OBJECTS) $(cwmpd_LDADD) $(LIBS)

mostlyclean-compile:
	-rm -f *.$(OBJEXT)

distclean-compile:
	-rm -f *.tab.c

include ./$(DEPDIR)/cwmpd-agent.Po
include ./$(DEPDIR)/cwmpd-conf.Po
include ./$(DEPDIR)/cwmpd-cwmpd.Po
include ./$(DEPDIR)/cwmpd-data_model.Po
include ./$(DEPDIR)/cwmpd-httpd.Po
include ./$(DEPDIR)/cwmpd-process.Po
include ./$(DEPDIR)/cwmpd-thread.Po

.c.o:
	$(AM_V_CC)$(COMPILE) -MT $@ -MD -MP -MF $(DEPDIR)/$*.Tpo -c -o $@ $<
	$(AM_V_at)$(am__mv) $(DEPDIR)/$*.Tpo $(DEPDIR)/$*.Po
#	$(AM_V_CC)source='$<' object='$@' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(COMPILE) -c $<

.c.obj:
	$(AM_V_CC)$(COMPILE) -MT $@ -MD -MP -MF $(DEPDIR)/$*.Tpo -c -o $@ `$(CYGPATH_W) '$<'`
	$(AM_V_at)$(am__mv) $(DEPDIR)/$*.Tpo $(DEPDIR)/$*.Po
#	$(AM_V_CC)source='$<' object='$@' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(COMPILE) -c `$(CYGPATH_W) '$<'`

.c.lo:
	$(AM_V_CC)$(LTCOMPILE) -MT $@ -MD -MP -MF $(DEPDIR)/$*.Tpo -c -o $@ $<
	$(AM_V_at)$(am__mv) $(DEPDIR)/$*.Tpo $(DEPDIR)/$*.Plo
#	$(AM_V_CC)source='$<' object='$@' libtool=yes \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(LTCOMPILE) -c -o $@ $<

cwmpd-conf.o: conf.c
	$(AM_V_CC)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(cwmpd_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -MT cwmpd-conf.o -MD -MP -MF $(DEPDIR)/cwmpd-conf.Tpo -c -o cwmpd-conf.o `test -f 'conf.c' || echo '$(srcdir)/'`conf.c
	$(AM_V_at)$(am__mv) $(DEPDIR)/cwmpd-conf.Tpo $(DEPDIR)/cwmpd-conf.Po
#	$(AM_V_CC)source='conf.c' object='cwmpd-conf.o' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(cwmpd_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -c -o cwmpd-conf.o `test -f 'conf.c' || echo '$(srcdir)/'`conf.c

cwmpd-conf.obj: conf.c
	$(AM_V_CC)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(cwmpd_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -MT cwmpd-conf.obj -MD -MP -MF $(DEPDIR)/cwmpd-conf.Tpo -c -o cwmpd-conf.obj `if test -f 'conf.c'; then $(CYGPATH_W) 'conf.c'; else $(CYGPATH_W) '$(srcdir)/conf.c'; fi`
	$(AM_V_at)$(am__mv) $(DEPDIR)/cwmpd-conf.Tpo $(DEPDIR)/cwmpd-conf.Po
#	$(AM_V_CC)source='conf.c' object='cwmpd-conf.obj' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(cwmpd_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -c -o cwmpd-conf.obj `if test -f 'conf.c'; then $(CYGPATH_W) 'conf.c'; else $(CYGPATH_W) '$(srcdir)/conf.c'; fi`

cwmpd-cwmpd.o: cwmpd.c
	$(AM_V_CC)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(cwmpd_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -MT cwmpd-cwmpd.o -MD -MP -MF $(DEPDIR)/cwmpd-cwmpd.Tpo -c -o cwmpd-cwmpd.o `test -f 'cwmpd.c' || echo '$(srcdir)/'`cwmpd.c
	$(AM_V_at)$(am__mv) $(DEPDIR)/cwmpd-cwmpd.Tpo $(DEPDIR)/cwmpd-cwmpd.Po
#	$(AM_V_CC)source='cwmpd.c' object='cwmpd-cwmpd.o' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(cwmpd_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -c -o cwmpd-cwmpd.o `test -f 'cwmpd.c' || echo '$(srcdir)/'`cwmpd.c

cwmpd-cwmpd.obj: cwmpd.c
	$(AM_V_CC)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(cwmpd_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -MT cwmpd-cwmpd.obj -MD -MP -MF $(DEPDIR)/cwmpd-cwmpd.Tpo -c -o cwmpd-cwmpd.obj `if test -f 'cwmpd.c'; then $(CYGPATH_W) 'cwmpd.c'; else $(CYGPATH_W) '$(srcdir)/cwmpd.c'; fi`
	$(AM_V_at)$(am__mv) $(DEPDIR)/cwmpd-cwmpd.Tpo $(DEPDIR)/cwmpd-cwmpd.Po
#	$(AM_V_CC)source='cwmpd.c' object='cwmpd-cwmpd.obj' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(cwmpd_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -c -o cwmpd-cwmpd.obj `if test -f 'cwmpd.c'; then $(CYGPATH_W) 'cwmpd.c'; else $(CYGPATH_W) '$(srcdir)/cwmpd.c'; fi`

cwmpd-httpd.o: httpd.c
	$(AM_V_CC)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(cwmpd_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -MT cwmpd-httpd.o -MD -MP -MF $(DEPDIR)/cwmpd-httpd.Tpo -c -o cwmpd-httpd.o `test -f 'httpd.c' || echo '$(srcdir)/'`httpd.c
	$(AM_V_at)$(am__mv) $(DEPDIR)/cwmpd-httpd.Tpo $(DEPDIR)/cwmpd-httpd.Po
#	$(AM_V_CC)source='httpd.c' object='cwmpd-httpd.o' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(cwmpd_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -c -o cwmpd-httpd.o `test -f 'httpd.c' || echo '$(srcdir)/'`httpd.c

cwmpd-httpd.obj: httpd.c
	$(AM_V_CC)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(cwmpd_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -MT cwmpd-httpd.obj -MD -MP -MF $(DEPDIR)/cwmpd-httpd.Tpo -c -o cwmpd-httpd.obj `if test -f 'httpd.c'; then $(CYGPATH_W) 'httpd.c'; else $(CYGPATH_W) '$(srcdir)/httpd.c'; fi`
	$(AM_V_at)$(am__mv) $(DEPDIR)/cwmpd-httpd.Tpo $(DEPDIR)/cwmpd-httpd.Po
#	$(AM_V_CC)source='httpd.c' object='cwmpd-httpd.obj' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(cwmpd_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -c -o cwmpd-httpd.obj `if test -f 'httpd.c'; then $(CYGPATH_W) 'httpd.c'; else $(CYGPATH_W) '$(srcdir)/httpd.c'; fi`

cwmpd-process.o: process.c
	$(AM_V_CC)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(cwmpd_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -MT cwmpd-process.o -MD -MP -MF $(DEPDIR)/cwmpd-process.Tpo -c -o cwmpd-process.o `test -f 'process.c' || echo '$(srcdir)/'`process.c
	$(AM_V_at)$(am__mv) $(DEPDIR)/cwmpd-process.Tpo $(DEPDIR)/cwmpd-process.Po
#	$(AM_V_CC)source='process.c' object='cwmpd-process.o' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(cwmpd_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -c -o cwmpd-process.o `test -f 'process.c' || echo '$(srcdir)/'`process.c

cwmpd-process.obj: process.c
	$(AM_V_CC)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(cwmpd_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -MT cwmpd-process.obj -MD -MP -MF $(DEPDIR)/cwmpd-process.Tpo -c -o cwmpd-process.obj `if test -f 'process.c'; then $(CYGPATH_W) 'process.c'; else $(CYGPATH_W) '$(srcdir)/process.c'; fi`
	$(AM_V_at)$(am__mv) $(DEPDIR)/cwmpd-process.Tpo $(DEPDIR)/cwmpd-process.Po
#	$(AM_V_CC)source='process.c' object='cwmpd-process.obj' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(cwmpd_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -c -o cwmpd-process.obj `if test -f 'process.c'; then $(CYGPATH_W) 'process.c'; else $(CYGPATH_W) '$(srcdir)/process.c'; fi`

cwmpd-thread.o: thread.c
	$(AM_V_CC)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(cwmpd_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -MT cwmpd-thread.o -MD -MP -MF $(DEPDIR)/cwmpd-thread.Tpo -c -o cwmpd-thread.o `test -f 'thread.c' || echo '$(srcdir)/'`thread.c
	$(AM_V_at)$(am__mv) $(DEPDIR)/cwmpd-thread.Tpo $(DEPDIR)/cwmpd-thread.Po
#	$(AM_V_CC)source='thread.c' object='cwmpd-thread.o' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(cwmpd_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -c -o cwmpd-thread.o `test -f 'thread.c' || echo '$(srcdir)/'`thread.c

cwmpd-thread.obj: thread.c
	$(AM_V_CC)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(cwmpd_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -MT cwmpd-thread.obj -MD -MP -MF $(DEPDIR)/cwmpd-thread.Tpo -c -o cwmpd-thread.obj `if test -f 'thread.c'; then $(CYGPATH_W) 'thread.c'; else $(CYGPATH_W) '$(srcdir)/thread.c'; fi`
	$(AM_V_at)$(am__mv) $(DEPDIR)/cwmpd-thread.Tpo $(DEPDIR)/cwmpd-thread.Po
#	$(AM_V_CC)source='thread.c' object='cwmpd-thread.obj' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(cwmpd_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -c -o cwmpd-thread.obj `if test -f 'thread.c'; then $(CYGPATH_W) 'thread.c'; else $(CYGPATH_W) '$(srcdir)/thread.c'; fi`

cwmpd-agent.o: agent.c
	$(AM_V_CC)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(cwmpd_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -MT cwmpd-agent.o -MD -MP -MF $(DEPDIR)/cwmpd-agent.Tpo -c -o cwmpd-agent.o `test -f 'agent.c' || echo '$(srcdir)/'`agent.c
	$(AM_V_at)$(am__mv) $(DEPDIR)/cwmpd-agent.Tpo $(DEPDIR)/cwmpd-agent.Po
#	$(AM_V_CC)source='agent.c' object='cwmpd-agent.o' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(cwmpd_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -c -o cwmpd-agent.o `test -f 'agent.c' || echo '$(srcdir)/'`agent.c

cwmpd-agent.obj: agent.c
	$(AM_V_CC)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(cwmpd_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -MT cwmpd-agent.obj -MD -MP -MF $(DEPDIR)/cwmpd-agent.Tpo -c -o cwmpd-agent.obj `if test -f 'agent.c'; then $(CYGPATH_W) 'agent.c'; else $(CYGPATH_W) '$(srcdir)/agent.c'; fi`
	$(AM_V_at)$(am__mv) $(DEPDIR)/cwmpd-agent.Tpo $(DEPDIR)/cwmpd-agent.Po
#	$(AM_V_CC)source='agent.c' object='cwmpd-agent.obj' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(cwmpd_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -c -o cwmpd-agent.obj `if test -f 'agent.c'; then $(CYGPATH_W) 'agent.c'; else $(CYGPATH_W) '$(srcdir)/agent.c'; fi`

cwmpd-data_model.o: modules/data_model.c
	$(AM_V_CC)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(cwmpd_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -MT cwmpd-data_model.o -MD -MP -MF $(DEPDIR)/cwmpd-data_model.Tpo -c -o cwmpd-data_model.o `test -f 'modules/data_model.c' || echo '$(srcdir)/'`modules/data_model.c
	$(AM_V_at)$(am__mv) $(DEPDIR)/cwmpd-data_model.Tpo $(DEPDIR)/cwmpd-data_model.Po
#	$(AM_V_CC)source='modules/data_model.c' object='cwmpd-data_model.o' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(cwmpd_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -c -o cwmpd-data_model.o `test -f 'modules/data_model.c' || echo '$(srcdir)/'`modules/data_model.c

cwmpd-data_model.obj: modules/data_model.c
	$(AM_V_CC)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(cwmpd_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -MT cwmpd-data_model.obj -MD -MP -MF $(DEPDIR)/cwmpd-data_model.Tpo -c -o cwmpd-data_model.obj `if test -f 'modules/data_model.c'; then $(CYGPATH_W) 'modules/data_model.c'; else $(CYGPATH_W) '$(srcdir)/modules/data_model.c'; fi`
	$(AM_V_at)$(am__mv) $(DEPDIR)/cwmpd-data_model.Tpo $(DEPDIR)/cwmpd-data_model.Po
#	$(AM_V_CC)source='modules/data_model.c' object='cwmpd-data_model.obj' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(cwmpd_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -c -o cwmpd-data_model.obj `if test -f 'modules/data_model.c'; then $(CYGPATH_W) 'modules/data_model.c'; else $(CYGPATH_W) '$(srcdir)/modules/data_model.c'; fi`

mostlyclean-libtool:
	-rm -f *.lo

clean-libtool:
	-rm -rf .libs _libs

ID: $(am__tagged_files)
	$(am__define_uniq_tagged_files); mkid -fID $$unique
tags: tags-am
TAGS: tags

tags-am: $(TAGS_DEPENDENCIES) $(am__tagged_files)
	set x; \
	here=`pwd`; \
	$(am__define_uniq_tagged_files); \
	shift; \
	if test -z "$(ETAGS_ARGS)$$*$$unique"; then :; else \
	  test -n "$$unique" || unique=$$empty_fix; \
	  if test $$# -gt 0; then \
	    $(ETAGS) $(ETAGSFLAGS) $(AM_ETAGSFLAGS) $(ETAGS_ARGS) \
	      "$$@" $$unique; \
	  else \
	    $(ETAGS) $(ETAGSFLAGS) $(AM_ETAGSFLAGS) $(ETAGS_ARGS) \
	      $$unique; \
	  fi; \
	fi
ctags: ctags-am

CTAGS: ctags
ctags-am: $(TAGS_DEPENDENCIES) $(am__tagged_files)
	$(am__define_uniq_tagged_files); \
	test -z "$(CTAGS_ARGS)$$unique" \
	  || $(CTAGS) $(CTAGSFLAGS) $(AM_CTAGSFLAGS) $(CTAGS_ARGS) \
	     $$unique

GTAGS:
	here=`$(am__cd) $(top_builddir) && pwd` \
	  && $(am__cd) $(top_srcdir) \
	  && gtags -i $(GTAGS_ARGS) "$$here"
cscopelist: cscopelist-am

cscopelist-am: $(am__tagged_files)
	list='$(am__tagged_files)'; \
	case "$(srcdir)" in \
	  [\\/]* | ?:[\\/]*) sdir="$(srcdir)" ;; \
	  *) sdir=$(subdir)/$(srcdir) ;; \
	esac; \
	for i in $$list; do \
	  if test -f "$$i"; then \
	    echo "$(subdir)/$$i"; \
	  else \
	    echo "$$sdir/$$i"; \
	  fi; \
	done >> $(top_builddir)/cscope.files

distclean-tags:
	-rm -f TAGS ID GTAGS GRTAGS GSYMS GPATH tags

distdir: $(DISTFILES)
	@srcdirstrip=`echo "$(srcdir)" | sed 's/[].[^$$\\*]/\\\\&/g'`; \
	topsrcdirstrip=`echo "$(top_srcdir)" | sed 's/[].[^$$\\*]/\\\\&/g'`; \
	list='$(DISTFILES)'; \
	  dist_files=`for file in $$list; do echo $$file; done | \
	  sed -e "s|^$$srcdirstrip/||;t" \
	      -e "s|^$$topsrcdirstrip/|$(top_builddir)/|;t"`; \
	case $$dist_files in \
	  */*) $(MKDIR_P) `echo "$$dist_files" | \
			   sed '/\//!d;s|^|$(distdir)/|;s,/[^/]*$$,,' | \
			   sort -u` ;; \
	esac; \
	for file in $$dist_files; do \
	  if test -f $$file || test -d $$file; then d=.; else d=$(srcdir); fi; \
	  if test -d $$d/$$file; then \
	    dir=`echo "/$$file" | sed -e 's,/[^/]*$$,,'`; \
	    if test -d "$(distdir)/$$file"; then \
	      find "$(distdir)/$$file" -type d ! -perm -700 -exec chmod u+rwx {} \;; \
	    fi; \
	    if test -d $(srcdir)/$$file && test $$d != $(srcdir); then \
	      cp -fpR $(srcdir)/$$file "$(distdir)$$dir" || exit 1; \
	      find "$(distdir)/$$file" -type d ! -perm -700 -exec chmod u+rwx {} \;; \
	    fi; \
	    cp -fpR $$d/$$file "$(distdir)$$dir" || exit 1; \
	  else \
	    test -f "$(distdir)/$$file" \
	    || cp -p $$d/$$file "$(distdir)/$$file" \
	    || exit 1; \
	  fi; \
	done
check-am: all-am
check: check-am
all-am: Makefile $(PROGRAMS)
installdirs:
	for dir in "$(DESTDIR)$(bindir)"; do \
	  test -z "$$dir" || $(MKDIR_P) "$$dir"; \
	done
install: install-am
install-exec: install-exec-am
install-data: install-data-am
uninstall: uninstall-am

install-am: all-am
	@$(MAKE) $(AM_MAKEFLAGS) install-exec-am install-data-am

installcheck: installcheck-am
install-strip:
	if test -z '$(STRIP)'; then \
	  $(MAKE) $(AM_MAKEFLAGS) INSTALL_PROGRAM="$(INSTALL_STRIP_PROGRAM)" \
	    install_sh_PROGRAM="$(INSTALL_STRIP_PROGRAM)" INSTALL_STRIP_FLAG=-s \
	      install; \
	else \
	  $(MAKE) $(AM_MAKEFLAGS) INSTALL_PROGRAM="$(INSTALL_STRIP_PROGRAM)" \
	    install_sh_PROGRAM="$(INSTALL_STRIP_PROGRAM)" INSTALL_STRIP_FLAG=-s \
	    "INSTALL_PROGRAM_ENV=STRIPPROG='$(STRIP)'" install; \
	fi
mostlyclean-generic:

clean-generic:

distclean-generic:
	-test -z "$(CONFIG_CLEAN_FILES)" || rm -f $(CONFIG_CLEAN_FILES)
	-test . = "$(srcdir)" || test -z "$(CONFIG_CLEAN_VPATH_FILES)" || rm -f $(CONFIG_CLEAN_VPATH_FILES)

maintainer-clean-generic:
	@echo "This command is intended for maintainers to use"
	@echo "it deletes files that may require special tools to rebuild."
clean: clean-am

clean-am: clean-binPROGRAMS clean-generic clean-libtool mostlyclean-am

distclean: distclean-am
	-rm -rf ./$(DEPDIR)
	-rm -f Makefile
distclean-am: clean-am distclean-compile distclean-generic \
	distclean-tags

dvi: dvi-am

dvi-am:

html: html-am

html-am:

info: info-am

info-am:

install-data-am:

install-dvi: install-dvi-am

install-dvi-am:

install-exec-am: install-binPROGRAMS

install-html: install-html-am

install-html-am:

install-info: install-info-am

install-info-am:

install-man:

install-pdf: install-pdf-am

install-pdf-am:

install-ps: install-ps-am

install-ps-am:

installcheck-am:

maintainer-clean: maintainer-clean-am
	-rm -rf ./$(DEPDIR)
	-rm -f Makefile
maintainer-clean-am: distclean-am maintainer-clean-generic

mostlyclean: mostlyclean-am

mostlyclean-am: mostlyclean-compile mostlyclean-generic \
	mostlyclean-libtool

pdf: pdf-am

pdf-am:

ps: ps-am

ps-am:

uninstall-am: uninstall-binPROGRAMS

.MAKE: install-am install-strip

.PHONY: CTAGS GTAGS TAGS all all-am check check-am clean \
	clean-binPROGRAMS clean-generic clean-libtool cscopelist-am \
	ctags ctags-am distclean distclean-compile distclean-generic \
	distclean-libtool distclean-tags distdir dvi dvi-am html \
	html-am info info-am install install-am install-binPROGRAMS \
	install-data install-data-am install-dvi install-dvi-am \
	install-exec install-exec-am install-html install-html-am \
	install-info install-info-am install-man install-pdf \
	install-pdf-am install-ps install-ps-am install-strip \
	installcheck installcheck-am installdirs maintainer-clean \
	maintainer-clean-generic mostlyclean mostlyclean-compile \
	mostlyclean-generic mostlyclean-libtool pdf pdf-am ps ps-am \
	tags tags-am uninstall uninstall-am uninstall-binPROGRAMS


# Tell versions [3.59,3.63) of GNU make to not export all variables.
# Otherwise a system limit (for SysV at least) may be exceeded.
.NOEXPORT:
