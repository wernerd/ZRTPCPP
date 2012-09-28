/*
 * lbn.h - Low-level bignum header.
 * Defines various word sizes and useful macros.
 * TODO: Rewrite this to use <stdint.h> and/or <inttypes.h>
 *
 * Copyright (c) 1995  Colin Plumb.  All rights reserved.
 * For licensing and other legal details, see the file legal.c.
 */
#ifndef LBN_H
#define LBN_H

#ifndef HAVE_CONFIG_H
#define HAVE_CONFIG_H 0
#endif
#if HAVE_CONFIG_H
#include <bnconfig.h>
#endif

/*
 * Some compilers complain about #if FOO if FOO isn't defined,
 * so do the ANSI-mandated thing explicitly...
 */
#ifndef NO_LIMITS_H
#define NO_LIMITS_H 0
#endif

#include <stdint.h>             /* TODO: protect by configuration ifdef */

/* Make sure we have 8-bit bytes */
#if !NO_LIMITS_H
#include <limits.h>
#if UCHAR_MAX != 0xff || CHAR_BIT != 8
#error The bignum library requires 8-bit unsigned characters.
#endif
#endif /* !NO_LIMITS_H */

#ifdef BNINCLUDE	/* If this is defined as, say, foo.h */
#define STR(x) #x	/* STR(BNINCLUDE) -> "BNINCLUDE" */
#define XSTR(x) STR(x)	/* XSTR(BNINCLUDE) -> STR(foo.h) -> "foo.h" */
#include XSTR(BNINCLUDE)	/* #include "foo.h" */
#undef XSTR
#undef STR
#endif

/* Do we want bnYield()? */
#ifndef BNYIELD
#define BNYIELD 0
#endif

/* Figure out the endianness */
/* Error if more than one is defined */
#if defined(BN_BIG_ENDIAN) && defined(BN_LITTLE_ENDIAN)
#error Only one of BN_BIG_ENDIAN or BN_LITTLE_ENDIAN may be defined
#endif

/*
 * If no preference is stated, little-endian C code is slightly more
 * efficient, so prefer that.  (The endianness here does NOT have to
 * match the machine's native byte sex; the library's C code will work
 * either way.  The flexibility is allowed for assembly routines
 * that do care.
 */
#if !defined(BN_BIG_ENDIAN) && !defined(BN_LITTLE_ENDIAN)
#define BN_LITTLE_ENDIAN 1
#endif /* !BN_BIG_ENDIAN && !BN_LITTLE_ENDIAN */

/* Macros to choose between big and little endian */
#if defined(BN_BIG_ENDIAN)
#define BIG(b) b
#define LITTLE(l) /*nothing*/
#define BIGLITTLE(b,l) b
#elif BN_LITTLE_ENDIAN
#define BIG(b) /*nothing*/
#define LITTLE(l) l
#define BIGLITTLE(b,l) l
#else
#error One of BN_BIG_ENDIAN or BN_LITTLE_ENDIAN must be defined as 1
#endif


/*
 * Define a 16-bit unsigned type if available.
 * Unsigned short is preferred over unsigned int to make the type chosen
 * by this file more stable on platforms (such as many 68000 compilers)
 * which support both 16- and 32-bit ints.
 */
#ifndef BNWORD16
#if !defined USHRT_MAX || USHRT_MAX == 0xffff ||  UINT_MAX == 0xffff
#define BNWORD16 uint16_t
#endif
#endif /* BNWORD16 */

/*
 * Define a 32-bit unsigned type if available.
 * Unsigned long is preferred over unsigned int to make the type chosen
 * by this file more stable on platforms (such as many 68000 compilers)
 * which support both 16- and 32-bit ints.
 */
#ifndef BNWORD32
#if !defined ULONG_MAX || ULONG_MAX == 0xfffffffful || UINT_MAX == 0xffffffff || USHRT_MAX == 0xffffffff
#define BNWORD32 uint32_t
#endif
#endif /* BNWORD32 */

/*
 * Find a 64-bit unsigned type.
 * The conditions here are more complicated to avoid using numbers that
 * will choke lesser preprocessors (like 0xffffffffffffffff) unless
 * we're reasonably certain that they'll be acceptable.
 */
#if !defined(BNWORD64) && ULONG_MAX > 0xffffffffUL
#if ULONG_MAX == 0xffffffffffffffff
#define BNWORD64 uint64_t
#endif
#endif

/*
 * I would test the value of unsigned long long, but some *preprocessors*
 * don't constants that long even if the compiler can accept them, so it
 * doesn't work reliably.  So cross our fingers and hope that it's a 64-bit
 * type.
 *
 * GCC uses ULONG_LONG_MAX.  Solaris uses ULLONG_MAX.  IRIX uses ULONGLONG_MAX.
 * Are there any other names for this?
 */
#if !defined(BNWORD64) && \
    (defined(ULONG_LONG_MAX) || defined (ULLONG_MAX) || defined(ULONGLONG_MAX))
#define BNWORD64 uint64_t
#endif

/* We don't even try to find a 128-bit type at the moment */

#endif /* !LBN_H */
