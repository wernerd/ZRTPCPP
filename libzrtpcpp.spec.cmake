#
# spec file for package libzrtpcpp (Version @VERSION@)
#
# Copyright (c) 2009 SUSE LINUX Products GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via http://bugs.opensuse.org/
#

Name:           libzrtpcpp
Summary:        A ccrtp extension for ZRTP support
BuildRequires:  gcc-c++ @BUILD_REQ@ pkgconfig cmake
BuildRequires:  libccrtp-devel >= 1.8.0 
Version:        @VERSION@
Release:        0
License:        GPL v3 or later
Group:          Development/Libraries/Other
Url:            http://www.gnu.org/software/commoncpp/commoncpp.html
Source0:        %{name}-%{version}.tar.bz2
Source1:        rpmlintrc
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
Provides:       %{name} = %{version}
Obsoletes:      %{name} < %{version}

%description
This library is a GPL licensed extension to the GNU RTP Stack, ccrtp,
that offers compatibility with Phil Zimmermann's zrtp/Zfone voice
encryption, and which can be directly embedded into telephony
applications.


%description -n libzrtpcpp
This library is a GPL licensed extension to the GNU RTP Stack, ccrtp,
that offers compatibility with Phil Zimmermann's zrtp/Zfone voice
encryption, and which can be directly embedded into telephony
applications.



%package devel
License:        GPL v3 or later
Group:          Development/Libraries/Other
Summary:        Headers and static link library for libzrtpcpp
Requires:       libzrtpcpp = %{version} libccrtp-devel

%description devel
This package provides the header files, link libraries, and
documentation for building applications that use libzrtpcpp.



%prep
%setup -q

%build
mkdir build
cd build

cmake -DCMAKE_INSTALL_PREFIX=%{_prefix} \
      -DSYSCONFDIR=%{_sysconfdir} \
      -DMANDIR=%{_mandir} \
      -DCMAKE_VERBOSE_MAKEFILE=TRUE \
      -DCMAKE_C_FLAGS_RELEASE:STRING="$RPM_OPT_FLAGS" \
      -DCMAKE_CXX_FLAGS_RELEASE:STRING="$RPM_OPT_FLAGS" \
      ..  

make %{?_smp_mflags}


# check
# make check

%install
cd build
make install DESTDIR=$RPM_BUILD_ROOT

%clean
rm -rf "$RPM_BUILD_ROOT"

%files -n libzrtpcpp
%defattr(-,root,root,0755)
%doc AUTHORS COPYING README
%{_libdir}/*.so.*

%files devel
%defattr(-,root,root,0755)
%{_libdir}/*.so
%{_libdir}/pkgconfig/*.pc
%{_includedir}/libzrtpcpp/*.h
%dir %{_includedir}/libzrtpcpp

%post -n libzrtpcpp -p /sbin/ldconfig

%postun -n libzrtpcpp -p /sbin/ldconfig

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
