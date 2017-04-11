Name:		syscall_intercept
Version:	0.1
Release:	1%{?dist}
Summary:	System call intercepting library
License:	BSD
URL:		http://github.com/pmem/syscall_intercept
Source0:	syscall_intercept-%{version}.tar.gz
#Source0:	https://github.com/pmem/syscall_intercept/archive/%{version}.tar.gz#/syscall_intercept-%{version}.tar.gz

BuildRequires:	glibc-devel
BuildRequires:	cmake
BuildRequires:	pkgconfig
BuildRequires:	capstone-devel

ExclusiveArch: x86_64

%description
 The system call intercepting library provides a low-level interface
 for hooking Linux system calls in user space. This is achieved
 by hotpatching the machine code of the standard C library in the
 memory of a process. The user of this library can provide the
 functionality of almost any syscall in user space, using the very
 simple API specified in the libsyscall_intercept_hook_point.h header
 file.

%package -n libsyscall_intercept
Summary: System call intercepting library
Group: System Environment/Libraries
%description -n libsyscall_intercept
The system call intercepting library provides a low-level interface
for hooking Linux system calls in user space. This is achieved
by hotpatching the machine code of the standard C library in the
memory of a process. The user of this library can provide the
functionality of almost any syscall in user space, using the very
simple API specified in the libsyscall_intercept_hook_point.h header
file.

%files -n libsyscall_intercept
%defattr(-,root,root,-)
%{_libdir}/libsyscall_intercept.so.*
%license LICENSE
%doc README.md

%package -n libsyscall_intercept-devel
Summary: Development files for libsyscall_intercept
Group: Development/Libraries
Requires: libsyscall_intercept = %{version}-%{release}
%description -n libsyscall_intercept-devel
Development files for libsyscall_intercept library

%files -n libsyscall_intercept-devel
%defattr(-,root,root,-)
%{_libdir}/libsyscall_intercept.so
%{_libdir}/libsyscall_intercept.a
%{_libdir}/pkgconfig/libsyscall_intercept.pc
%{_includedir}/libsyscall_intercept_hook_point.h
%{_mandir}/man3/libsyscall_intercept.3.gz
%license LICENSE
%doc

%prep
%setup -q -n %{name}-%{version}

%build
mkdir build && cd build
%cmake -DCMAKE_BUILD_TYPE=Release ..
make %{?_smp_mflags}

%install
cd build
make install DESTDIR=%{buildroot}

%check
cd build
ctest -V %{?_smp_mflags}

%post   -n libsyscall_intercept -p /sbin/ldconfig
%postun -n libsyscall_intercept -p /sbin/ldconfig

%changelog
* Tue Feb 14 2017 Marcin Ślusarz <marcin.slusarz@intel.com> - 0.1-1
- Initial RPM release
