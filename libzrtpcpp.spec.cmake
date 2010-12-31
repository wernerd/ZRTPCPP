# Copyright (c) 2008, 2009 David Sugar, Tycho Softworks.
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY, to the extent permitted by law; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.

%{!?release: %define release 0}

Summary: A ccrtp extension for zrtp/Zfone support
Name: libzrtpcpp
Version: @VERSION@
Release: 0%{?dist}
License: GPLv3+
Group: Development/Libraries
URL: http://www.gnu.org/software/commoncpp/commoncpp.html
Source0: ftp://ftp.gnu.org/gnu/ccrtp/%{name}-%{version}.tar.gz
Provides: %{name} = %{version}-%{release}
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
BuildRequires: libccrtp-devel >= 1.8.0
BuildRequires: pkgconfig
BuildRequires: libstdc++-devel
BuildRequires: @BUILD_REQ@
Requires: @PACKAGE_REQ@
Requires: ccrtp >= 1.8.0

%define srcdirname %{name}-%{version}

%description
This library is a GPL licensed extension to the GNU RTP Stack (GNU ccrtp).
This extension offers a C++ implementation of Phil Zimmermann's ZRTP 
specification. The current release is based on 
draft-zimmermann-avt-zrtp-16.txt which is intended to become the RFC. 
Phil's Zfone site provides more  information, see 
http://zfoneproject.com/index.html

This implementation was tested to work with Phil's Zfone implementations. 

Applications that use GNU ccrtp can use this library to use ZRTP and to
encrypt any RTP (not RTCP) communication. See the demo programs how to
use this.

This release supports the basic ZRTP features, it does not support
preshared specified in the draft. Also the specified Asterisk PBX mode
is not supported. 

# The developement subpackage
%package devel
Group: Development/Libraries
Summary: Headers for libzrtpcpp.
Requires: %{name} = %{version}-%{release}
Requires: libccrtp-devel >= 1.8.0
Requires: @BUILD_REQ@

%description devel
This package provides the header files, link libraries, and
documentation for building applications that use libzrtpcpp.

%prep
%setup -q

%build
cd ..
%{__rm} -rf build_tree
%{__mkdir} build_tree
cd build_tree
cmake -DCMAKE_INSTALL_PREFIX=%{buildroot}%{_prefix} ../%{srcdirname}
%{__make}

%install 
cd ../build_tree
%{__make} install

%clean
%{__rm} -rf %{buildroot}
%{__rm} -rf build_tree

%files 
%defattr(-,root,root,-)
%doc AUTHORS COPYING README NEWS INSTALL ChangeLog
%{_libdir}/*.so.*

%files devel
%defattr(-,root,root,-)
%{_libdir}/*.so
%{_libdir}/pkgconfig/*.pc
%{_includedir}/libzrtpcpp/

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%changelog
* Mon Dec 27 2010 - Werner Dittmann <werner.dittmann@t-online.de>
- Add Skein MAC authentication algorithm
- lots of documentation added (doxygen ready)
- some code cleanup

* Sun Oct 11 2009 - Werner Dittmann <werner.dittmann@t-online.de>
- Fix multistream problem
- add DH2048 mode
- update cipher selection to match latest draft (15x)
- Test with zfone3 with Ping packet mode enabled
- some code cleanup

* Wed Jun 24 2009 - David Sugar <dyfet@gnutelephony.org>
- Spec updated per current Fedora & CentOS policies.
- Updated release 1.4.5 has all mandatory IETF interop requirements.

* Fri Jan 26 2009 - Werner Dittmann <werner.dittmann@t-online.de>
- Update to version 1.4.2 to support the latest ZRTP
  specification draft-zimmermann-avt-zrtp-12

* Fri Aug 22 2008 - David Sugar <dyfet@gnutelephony.org>
- Adapted for newer library naming conventions.

* Tue Dec 11 2007 - Werner Dittmann <werner.dittmann@t-online.de>
- this is the first spec file for version 1.x.x
- remove the .la file in devel package
- use default file atttribute instead of 755

* Sat Apr 18 2007 - Werner Dittmann <werner.dittmann@t-online.de>
- set version to 1.1.0
- GNU ZRTP is compatible with the latest Zfone Beta
  from April 2 2007
