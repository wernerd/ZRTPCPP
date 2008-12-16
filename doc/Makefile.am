# Copyright (C) 2000-2005 Open Source Telecom Corporation.
# Copyright (C) 2006-2008 David Sugar, Tycho Softworks.
#  
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without 
# modifications, as long as this notice is preserved.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

AUTOMAKE_OPTIONS = no-dependencies
EXTRA_DIST = Doxymini

# info_TEXINFOS = ccrtp.texi
zrtp_TEXINFOS = gpl.texi fdl.texi fdlnotice.texi

if DOXY
noinst_DATA = doxy

doxy:   Doxymini
	(cd @srcdir@ ; $(DOXYGEN) Doxymini)
#	touch doxy

endif


