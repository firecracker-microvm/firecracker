Name:           firecracker-binary
Version:        v0.21.1
Release:        1%{?dist}
Summary:        Open source virtualization technology

License:        Apache License 2.0
URL:            https://github.com/firecracker-microvm/firecracker
Source0:        https://github.com/firecracker-microvm/firecracker/releases/download/v0.21.1/firecracker-v0.21.1-x86_64
Source1:        https://github.com/firecracker-microvm/firecracker/releases/download/v0.21.1/jailer-v0.21.1-x86_64
Source2:        firecracker@.service
BuildArch:      x86_64

BuildRequires:  systemd

Requires(post): systemd systemd-sysv chkconfig
Requires(preun): systemd
Requires(postun): systemd

%description
Firecracker is an open source virtualization technology that is purpose-built for creating and managing secure, multi-tenant container and function-based services that provide serverless operational models. Firecracker runs workloads in lightweight virtual machines, called microVMs, which combine the security and isolation properties provided by hardware virtualization technology with the speed and flexibility of containers.

%build

%install

rm -rf %{buildroot}

mkdir -p %{buildroot}%{_sbindir} \
        %{buildroot}%{_var}/lib/firecracker/{kernels,rootfs,microvm,metrics} \
        %{buildroot}%{_var}/run/firecracker \
        %{buildroot}%{_var}/log/firecracker \
        %{buildroot}%{_sysconfdir}/firecracker \
        %{buildroot}%/usr/share/firecracker/scripts

install -d -m 0755 %{buildroot}/etc/firecracker
install -d -m 0755 %{buildroot}/usr/share/firecracker
install -d -m 0755 %{buildroot}/usr/share/firecracker/scripts
install -d -m 0755 %{buildroot}/var/lib/firecracker
install -d -m 0755 %{buildroot}/var/lib/firecracker/kernels
install -d -m 0755 %{buildroot}/var/lib/firecracker/rootfs
install -d -m 0755 %{buildroot}/var/lib/firecracker/microvm
install -d -m 0755 %{buildroot}/var/lib/firecracker/metrics
install -d -m 0755 %{buildroot}/var/run/firecracker
install -d -m 0755 %{buildroot}/var/log/firecracker

install -m 0755 %{SOURCE0} %{buildroot}/%{_sbindir}/firecracker
install -m 0755 %{SOURCE1} %{buildroot}/%{_sbindir}/jailer

mkdir -p %{buildroot}%{_unitdir}
install -m644 %{SOURCE2} %{buildroot}%{_unitdir}

%clean
rm -rf %{buildroot}

%post
%systemd_post firecracker@.service

%preun
%systemd_preun firecracker@.service

%postun
%systemd_postun_with_restart firecracker@.service

%files
%defattr(-,root,root,-)
%dir /etc/firecracker
%dir /usr/share/firecracker
%dir /usr/share/firecracker/scripts
%dir /var/lib/firecracker
%dir /var/lib/firecracker/kernels
%dir /var/lib/firecracker/rootfs
%dir /var/lib/firecracker/microvm
%dir /var/lib/firecracker/metrics
%dir /var/run/firecracker
%dir /var/log/firecracker
%{_sbindir}/firecracker
%{_sbindir}/jailer
%{_unitdir}/firecracker@.service
%doc



%changelog
* Mon May 18 2020 Nurmukhamed Artykaly <nurmukhamed.artykaly@hdfilm.kz> v0.21.1-1
- Initial spec file