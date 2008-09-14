# Copyright (C) 1999-2004 Open Source Telecom Corporation.
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

AUTOMAKE_OPTIONS = no-dependencies dist-shar
LT_VERSION=@LT_CCXX_VERSION@
#ignored for programs
#$(LT_VERSION) -release $(LT_RELEASE)
AM_CXXFLAGS = @WARN_FLAGS@ -I$(top_srcdir)/src

noinst_PROGRAMS = zrtptest zrtptestMulti

zrtptest_SOURCES = zrtptest.cpp
zrtptest_LDFLAGS = ../src/libzrtpcpp.la

zrtptestMulti_SOURCES = zrtptestMulti.cpp
zrtptestMulti_LDFLAGS = ../src/libzrtpcpp.la