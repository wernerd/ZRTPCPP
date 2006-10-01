AC_PREREQ([2.50])
AC_INIT([libzrtpcpp], [0.9.0])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([libzrtpcpp], [0.9.0])

REQUIRESCCRTP="ccrtp >= 1.5.0"
AC_SUBST(REQUIRESCCRTP)

REQUIRES="1.3.0"
LT_RELEASE="0.9"
LT_VERSION="0:1"

# checks for progs
AC_PROG_CXX
AC_PROG_LIBTOOL

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

# PKG_CHECK_MODULES(CCRTP, libccrtp1 >= 1.3.4)

AC_CHECK_HEADERS([stdlib.h string.h pthread.h])

# we need the pthread library as well
AC_CHECK_LIB([pthread], [pthread_mutex_init], [], AC_MSG_ERROR([pthread library not found.]))

AC_CHECK_LIB([gcrypt],
             [gcry_cipher_open], [
                CRYPTOBACKEND="libccrtp1 >= 1.4.1"
                LIBS="-lgcrypt -lccrtp1 $LIBS"
                ],
             [AC_CHECK_LIB([crypto],
                           [EVP_CipherInit_ex], [
                                CRYPTOBACKEND="libcrypto >= 0.9.8. libccrtp1 >= 1.4.1"
                                LIBS="-lcrypto -lccrtp1 $LIBS"
                                ],
                           [AC_MSG_ERROR([Cannot find libgcrypt or OpenSSL crypto library.])]
                          )
             ]
            )
AM_CONDITIONAL(ZRTP_GCRYPT, test "${ac_cv_lib_gcrypt_gcry_cipher_open}" = "yes")
AM_CONDITIONAL(ZRTP_OPENSSL, test "${ac_cv_lib_crypto_EVP_CipherInit_ex}" = "yes")

OST_PROG_COMMON
OST_PROG_LIBVER
OST_PROG_LIBRARY(CCXX,[$LT_VERSION])
OST_AUTOMAKE_MODE
OST_MAINTAINER_MODE
OST_CCXX2_VERSION([$REQUIRES])
# OST_CC_ENDIAN - now in Common C++
# Are we using the GNU compiler?
if test $GCC = yes ; then
        WARN_FLAGS="-Wall -ansi -pedantic"
else
        WARN_FLAGS=""
fi
AC_SUBST(WARN_FLAGS)

OST_DEBUG

# AC_CHECK_HEADER([ccrtp/rtp.h],
#                [LIBS="-lccrtp1 $LIBS"],
#                [AC_MSG_ERROR([Cannot find GNU ccRTP header - install it before using libzrtpcpp])])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdlib.h string.h pthread.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST

# Checks for library functions.
AC_FUNC_MALLOC

AC_SUBST(CRYPTOBACKEND)
AC_CONFIG_FILES([Makefile src/Makefile src/libzrtpcpp/Makefile src/libzrtpcpp/crypto/Makefile])
AC_OUTPUT(libzrtpcpp.pc libzrtpcpp.spec)
