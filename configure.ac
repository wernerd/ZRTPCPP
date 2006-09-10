AC_PREREQ([2.50])
AC_INIT([libzrtpcpp], [0.9.0])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([libzrtpcpp], [0.9.0])

REQUIRES="1.3.0"

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

AC_CHECK_LIB([gcrypt],
             [gcry_cipher_open], [
                CRYPTOBACKEND="libgcrypt >= 1.1"
                LIBS="-lgcrypt $LIBS"
                ],
             [AC_CHECK_LIB([crypto],
                           [EVP_CipherInit_ex], [
                                CRYPTOBACKEND="openSSL >= 0.9.8"
                                LIBS="-lcrypto $LIBS"
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

# Checks for header files.
AC_HEADER_STDC

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST

# Checks for library functions.
AC_FUNC_MALLOC

AC_SUBST(CRYPTOBACKEND)
AC_CONFIG_FILES([Makefile src/Makefile src/libzrtpcpp/Makefile src/libzrtpcpp/crypto/Makefile])
AC_OUTPUT(libzrtpcpp.pc)
