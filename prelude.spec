%define name prelude
%define majver 0
%define version 0.4.0
%define release 1mdk

Summary: An Hybrid Intrusion Detection System
Name: %{name}
Version: %{version}
Release: %{release}
Source0: %{name}-%{version}.tar.bz2
Source1: prelude.init
Copyright: GPL
Group: Networking/Other
BuildRoot: /var/tmp/prelude
Provides: prelude = %{version}-%{release}
Requires: libprelude = %{version}-%{release}

%package -n libprelude%{majver}
Summary: Shared code between Prelude, Prelude Report, and plugins.
Group: System/Libraries
Provides: libprelude = %{version}-%{release}

%package -n prelude-doc
Summary: Prelude API documentation.
Group: Books/Other
Provides: prelude-doc = %{version}-%{release}

%package -n prelude-report
Summary: The Prelude Report server
Group: System/Servers
Provides: prelude-report = %{version}-%{release}
Requires: libprelude = %{version}-%{release}, openssl


%description
Prelude is an Hybrid Intrusion Detection System, written entirely from scratch, in C.

Prelude is divided in several parts:
* The Prelude NIDS sensor, responssible for real time packet capture and
  analysis :

 - The signature engine, designed to be completly generic and evolutive, it is
   currently able to read Snort rulesets. By simply adding parser, it should
   permit to load rulesets from any NIDS easily.

 - The protocol plugins, which can handle packets at a higher level than prelude
   do, ie: you got a tcp packet, and a Protocol plugin detect that packet data
   contain an ssh header, so it will decode the ssh header, and ask to the
   associated Detection plugin to analyze the decoded header.

 - A set of detection plugins which job is to analyze the data they are
   interested in (they register the protocol they are interested in at
   initialization time), and will eventually emmit a security warning. Dection
   plugin should only be used for complex intrusion detection that can't be
   done using the signature engine.

* A report server, which sensors contact in order to report an alert, that
  generates user readable report using plugins.

 - The reporting plugins, which job is to decode the reports issued by
   Detection plugin, and translate them in an user readable form (ex: syslog
   report, html report, etc).


%description -n libprelude%{majver}
This library contain shared code between Prelude, Prelude Report,
and their respective plugins. 


%description -n prelude-report
The main task of the Prelude Report server is to get alert from 
Prelude sensors and generate user readable report with the gathered alerts.
The reports are generated using plugins.

%description -n prelude-doc
Prelude API documentation.


%prep
%setup 

%build
%configure
%make

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT
%makeinstall

echo "PRELUDE_INTERFACES=eth0" > $RPM_BUILD_ROOT/%{_sysconfdir}/prelude-init.conf

mkdir -p $RPM_BUILD_ROOT%{_initrddir}
install -m 755 $RPM_SOURCE_DIR/prelude.init \
	$RPM_BUILD_ROOT%{_initrddir}/prelude

%clean
rm -rf $RPM_BUILD_ROOT

%post -n libprelude%{majver} -p /sbin/ldconfig
%postun -n libprelude%{majver} -p /sbin/ldconfig

%files -n libprelude%{majver}
%defattr(-,root,root)
%{_libdir}/libprelude.so.*

%files -n prelude
%defattr(-,root,root)
%doc AUTHORS COPYING ChangeLog NEWS README TODO CREDITS
%{_bindir}/prelude
%{_libdir}/prelude/detects/*
%{_libdir}/prelude/protocols/*
%{_localstatedir}/prelude
%config %{_sysconfdir}/prelude/prelude.conf
%config(noreplace) %{_initrddir}/prelude
%config(noreplace) %{_sysconfdir}/prelude-init.conf



%files -n prelude-report
%defattr(-,root,root)
%{_bindir}/prelude_report
%{_libdir}/prelude/reports/*
%{_localstatedir}/prelude
%config %{_sysconfdir}/prelude/prelude-report.conf
%config(noreplace) %{_initrddir}/prelude



%files -n prelude-doc
%defattr(-,root,root)
%{_docdir}/prelude


%changelog
* Fri Aug 17 2001 Yoann Vandoorselaere <yoann@mandrakesoft.com> 0.4.0-1mdk

- Update to 0.4.0

* Thu Mar 29 2001 Yoann Vandoorselaere <yoann@mandrakesoft.com> 0.3-1mdk
- first packaging attempt.










