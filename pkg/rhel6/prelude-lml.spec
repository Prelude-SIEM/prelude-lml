Name:  prelude-lml
Epoch:  1
Version: 1.0.1
Release: 1%{?dist}
Summary: The prelude log analyzer

Group:  System Environment/Libraries
License: GPLv2+
URL:  http://prelude-ids.com/
Source0: http://www.prelude-ids.com/download/releases/%{name}/%{name}-%{version}.tar.gz
Source1:        prelude-lml.init
#Patch1:  prelude-lml-1.0.0rc1-pie.patch
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires: gamin-devel, pcre-devel
BuildRequires: libprelude-devel >= 0.9.21.3
Requires(post): /sbin/chkconfig
Requires(preun): /sbin/chkconfig
Requires(preun): /sbin/service
Requires(postun): /sbin/service

%description
Prelude-LML is a log analyser that allows Prelude to collect and
analyze information from all kind of applications emitting logs or
syslog messages in order to detect suspicious activities and transform
them into Prelude-IDMEF alerts. Prelude-LML handles events generated
by a large set of applications,

%package devel
Summary: Header files and libraries for libprelude development
Group: Development/Libraries
Requires: libprelude-devel, prelude-lml = %{epoch}:%{version}-%{release}

%description devel
Libraries, include files, etc you can use to develop custom
Prelude LML plugins.


%prep
%setup -q
%patch1 -p1


%build
%configure
make %{?_smp_mflags}


%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/%{_initrddir}/
mkdir -p %{buildroot}/var/lib/%{name}/
make install DESTDIR=%{buildroot} INSTALL="%{__install} -c -p"
install -m 755 %{SOURCE1} %{buildroot}/%{_initrddir}/%{name}
rm -f %{buildroot}/%{_libdir}/%{name}/debug.la
rm -f %{buildroot}/%{_libdir}/%{name}/pcre.la

%clean
rm -rf %{buildroot}

%post
/sbin/ldconfig
/sbin/chkconfig --add %{name}

%preun
if [ $1 = 0 ]; then
        /sbin/service %{name} stop > /dev/null 2>&1 || :
        /sbin/chkconfig --del %{name}
fi

%postun
/sbin/ldconfig
if [ "$1" -ge "1" ]; then
        /sbin/service %{name} condrestart >/dev/null 2>&1 || :
fi


%files
%defattr(-,root,root,-)
%doc COPYING
%attr(0750,root,root) %dir %{_sysconfdir}/%{name}/
%config(noreplace) %attr(0640,root,root) %{_sysconfdir}/%{name}/*.conf
%config(noreplace) %attr(0640,root,root) %{_sysconfdir}/%{name}/*.rules
%attr(0750,root,root) %dir %{_sysconfdir}/%{name}/ruleset/
%config(noreplace) %attr(0640,root,root)%{_sysconfdir}/%{name}/ruleset/*
%{_initrddir}/%{name}
%{_bindir}/prelude-lml
%dir %{_libdir}/%{name}/
%{_libdir}/%{name}/debug.so
%{_libdir}/%{name}/pcre.so
%attr(0750,root,root) %dir /var/lib/%{name}/

%files devel
%defattr(-,root,root,-)
%dir %{_includedir}/%{name}/
%{_includedir}/%{name}/prelude-lml.h


%changelog
* Wed Jun 15 2011 Vincent Quéméner <vincent.quemener@c-s.fr> - 1.0.0-5
- Rebuilt for RHEL6

* Wed Feb 09 2011 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1:1.0.0-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

* Sun May 02 2010 Steve Grubb <sgrubb@redhat.com> 1.0.0-3
- Fixed requires

* Fri Apr 30 2010 Steve Grubb <sgrubb@redhat.com> 1.0.0-2
- new upstream release

* Mon Feb 08 2010 Steve Grubb <sgrubb@redhat.com> 1.0.0rc2-1
- new upstream release

* Sat Jan 30 2010 Steve Grubb <sgrubb@redhat.com> 1.0.0rc1-1
- new upstream release

* Sun Jul 26 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.9.15-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

* Tue Jul 21 2009 Steve Grubb <sgrubb@redhat.com> 0.9.15-1
- new upstream release

* Wed Apr 22 2009 Steve Grubb <sgrubb@redhat.com> 0.9.14-3
- Adjust dir and config file permissions

* Thu Feb 26 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.9.14-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

* Fri Oct 17 2008 Steve Grubb <sgrubb@redhat.com> 0.9.14-1
- new upstream release fixing bz #463459

* Sat Oct 11 2008 Steve Grubb <sgrubb@redhat.com> 0.9.13-2
- improved mod_security rules

* Wed Aug 27 2008 Steve Grubb <sgrubb@redhat.com> 0.9.13-1
- new upstream release

* Wed Jun 25 2008 Tomas Mraz <tmraz@redhat.com> - 0.9.12.2-2
- rebuild with new gnutls

* Thu Apr 24 2008 Steve Grubb <sgrubb@redhat.com> 0.9.12.2-1
- new upstream release

* Wed Feb 20 2008 Fedora Release Engineering <rel-eng@fedoraproject.org> - 0.9.11-2
- Autorebuild for GCC 4.3

* Mon Jan 14 2008 Steve Grubb <sgrubb@redhat.com> 0.9.11-1
- new upstream version 0.9.11

* Thu Jan 09 2007 Thorsten Scherf <tscherf@redhat.com> 0.9.8.1-5
- changed init-script description

* Mon Jan 08 2007 Thorsten Scherf <tscherf@redhat.com> 0.9.8.1-4
- added new /var/lib directory

* Fri Jan 05 2007 Thorsten Scherf <tscherf@redhat.com> 0.9.8.1-3
- added init-script
- changed some macros in %%files

* Tue Jan 02 2007 Thorsten Scherf <tscherf@redhat.com> 0.9.8.1-2
- fixed debug problems
- fixed encoding problems

* Fri Dec 29 2006 Thorsten Scherf <tscherf@redhat.com> 0.9.8.1-1
- moved to new upstream version 0.9.8.1
- changed dirowner of /etc/prelude-lml

* Mon Nov 20 2006 Thorsten Scherf <tscherf@redhat.com> 0.9.7-2
- Some minor fixes in requirements

* Tue Oct 23 2006 Thorsten Scherf <tscherf@redhat.com> 0.9.7-1
- New Fedora build based on release 0.9.7
