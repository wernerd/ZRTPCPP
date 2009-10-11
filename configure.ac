# Copyright (C) 2006, 2007 Werner Dittmen
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
AC_INIT(src/ZRtp.cxx)

# LT_VERSION actually is meant to be in the form ABI-LINK_VER:ABI_PATCH_VER. 
# This eventaully goes into libtool as "version-info" (via LT_CCXX_VERSION in
# Makefile.am). LT_RELEASE goes into libtool as "release".
#
# Hence, if the binary api is not changed for a given release, 1.0.0 should have:
#
# VERSION=1.0.0
# LT_RELEASE=1.0
# LT_VERSION=0:0
#
# VERSION=1.0.1 might have either LT_VERSION=0:1 if binary linking remains
# unchanged, or LT_VERSION=1:0 if binary linking is changed.
# (see macros "OST_PROG_LIBVER" and "OST_PROG_LIBRARY" below)
#
VERSION="1.4.6"
# AC_INIT([libzrtpcpp], [1.0.0] )
# AC_CONFIG_SRCDIR([configure.ac])

LT_RELEASE="1.4"
LT_VERSION="0:6"

REQUIRES="1.3.0"

cfg_options=""
if test -z "$*" ; then
        if test -f ~/.configure ; then
	        cfg_options=`grep ^ccrtp: ~/.configure | sed -e s/^ccrtp://`
        elif test -f /etc/configure.conf ; then
	        cfg_options=`grep ^ccrtp: /etc/configure.conf | sed -e s/^ccrtp://`
        fi
fi

if test ! -z "$cfg_options" ; then
        echo "using ~/.configure defaults...$cfg_options"
        case "$SHELL" in
        */bash*)
                exec $SHELL $0 $cfg_options
                exit -1
                ;;
        esac
        exec $0 $cfg_options
        exit -1
fi

AC_CONFIG_AUX_DIR(autoconf)
AC_CANONICAL_SYSTEM
AC_PROG_CPP
AC_PROG_CXXCPP
AC_PROG_CXX
AM_PROG_LIBTOOL
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([libzrtpcpp], [$VERSION])
# AM_INIT_AUTOMAKE

AC_C_RESTRICT
AC_C_VOLATILE
AC_C_INLINE

if test -z "$PKG_CONFIG_PATH" ; then
        PKG_CONFIG_PATH="/usr/local/lib/pkgconfig:/usr/lib/pkgconfig"
fi

if test "$prefix" != "NONE" ; then
        PKG_CONFIG_PATH="$prefix/lib/pkgconfig:$PKG_CONFIG_PATH"
fi

export PKG_CONFIG_PATH

# use "-no-undefined" on Cygwin to force (trigger) libtool to create
# the shared lib. If this is not set this library
# is not created. Be sure that the LIBS variable above contains _all_
# libraries necessary to build ours, Cygwin does not allow undefined
# symbols.
case $host in
#  *-*-msdos* | *-*-go32* | *-*-mingw32* | *-*-cygwin* | *-*-windows*)
  *-*-cygwin*)
	LDFLAGS="$LDFLAGS -no-undefined"
    ;;
  *)
    ;;
esac

AC_CHECK_HEADERS([stdlib.h string.h pthread.h])

# we need the pthread library as well
AC_CHECK_LIB([pthread], [pthread_mutex_init], [], AC_MSG_ERROR([pthread library not found.]))

openssl="false"
gcrypt="false"
AM_PATH_LIBGCRYPT_CCRTP([1:1.2.3],
                  [AC_CHECK_HEADERS([gcrypt.h],
                                    [], AC_MSG_ERROR([libgcrypt headers not found.]))
                    CRYPTOBACKEND=""
                    PACKAGE_REQ="libgcrypt"
                    BUILD_REQ="libgcrypt-devel"
                    LIBS="$LIBGCRYPT_LIBS $LIBS"
                    gcrypt="true"
                  ],
                  [AC_CHECK_LIB([crypto],
                    [EVP_CipherInit_ex],
                    [AC_CHECK_HEADERS([openssl/bn.h openssl/aes.h openssl/sha.h],
                                        [], AC_MSG_ERROR([OpenSSL headers not found.]))
                      CRYPTOBACKEND="libcrypto >= 0.9.8"
                      PACKAGE_REQ="libopenssl >= 0.9.8"
                      BUILD_REQ="libopenssl-devel >= 0.9.8"

                      LIBS="-lcrypto $LIBS"
                      openssl="true"
                    ],
                    [AC_MSG_ERROR([Cannot find libgcrypt or OpenSSL crypto library.])]
                  ]
                  )
                 )
# don't forget AM_CONDITIONALs, see blow
AM_CONDITIONAL(ZRTP_OPENSSL, test "$openssl" = "true")
AM_CONDITIONAL(ZRTP_GCRYPT, test "$gcrypt" = "true")

OST_PROG_COMMON
OST_PROG_LIBVER
OST_PROG_LIBRARY(CCXX,[$LT_VERSION])
OST_AUTOMAKE_MODE
OST_MAINTAINER_MODE
# OST_CC_ENDIAN - now in Common C++
# Are we using the GNU compiler?
if test x"$GCC" = xyes ; then
		CXXFLAGS="$CXXFLAGS -Wno-long-long -Wno-char-subscripts"
        WARN_FLAGS="-Wall -ansi -pedantic"
else
        WARN_FLAGS=""
fi
AC_SUBST(WARN_FLAGS)

AC_ARG_WITH([ccrtp],
            [AS_HELP_STRING([--without-ccrtp], [disable support for ccrtp, @<:@default=yes@:>@])],
            [],
            [with_ccrtp=yes])

if test "x$with_ccrtp" != xno; then
    PKG_CHECK_MODULES(RTPSTACK, libccrtp1 >= 1.5.0, [
        RTPSTACK_LIBPATH=`pkg-config --variable=libdir libccrtp1`
        LIBS="-L$RTPSTACK_LIBPATH $RTPSTACK_LIBS $LIBS"
        CCXX_FLAGS="$CXXFLAGS $RTPSTACK_CFLAGS"
    ])
    PKG_CHECK_MODULES(COMMON, libccgnu2 >= $REQUIRES)
    CXXFLAGS="$CXXFLAGS $COMMON_CFLAGS"
    COMMON_LIBPATH=`pkg-config --variable=libdir libccgnu2`
    LIBS="-L$COMMON_LIBPATH $COMMON_LIBS $LIBS"
    CRYPTOBACKEND="$CRYPTOBACKEND libccrtp1 >= 1.5.0"
fi
AM_CONDITIONAL(CCRTP_SUPPORT, test "${with_ccrtp}" = "yes")

OST_DEBUG

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdlib.h string.h pthread.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST

# Checks for library functions.
AC_FUNC_MALLOC

# Check for documentation formatter
AC_PATH_PROG(DOXYGEN, doxygen, no)
AC_SUBST(DOXYGEN)
AM_CONDITIONAL(DOXY, test "$DOXYGEN" != "no")

AC_SUBST(LT_VERSION)
AC_SUBST(CRYPTOBACKEND)
AC_SUBST(PACKAGE_REQ)
AC_SUBST(BUILD_REQ)
AC_CONFIG_FILES([Makefile src/Makefile src/libzrtpcpp/Makefile m4/Makefile
                src/libzrtpcpp/crypto/Makefile doc/Makefile demo/Makefile
                libzrtpcpp.pc libzrtpcpp.spec])  # m4/Makefile
AC_OUTPUT
