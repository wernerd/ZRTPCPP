# Copyright (C) 2006 Warner Dittman
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

AUTOMAKE_OPTIONS = foreign
SUBDIRS = src
DIST_SUBDIRS = m4 src doc demo

EXTRA_DIST = README AUTHORS COPYING INSTALL NEWS \
	libzrtpcpp.pc.in libzrtpcpp.spec.in autogen.sh autoconf/*

ACLOCAL_AMFLAGS = -I m4

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libzrtpcpp.pc
