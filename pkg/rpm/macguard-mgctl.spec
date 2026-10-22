# TEMPLATE for a Fedora/RHEL package (not built, not submitted). `rpmbuild` was not available when this was written: build and test it on a real Fedora/RHEL system.
# Installs only /usr/bin/mgctl and /usr/lib/mgctl; it never provides "mg" (that name belongs to the mg editor package).
Name:           macguard-mgctl
Version:        0.1.0
Release:        1%{?dist}
Summary:        mgctl, the canonical command of the MacGuard suite
License:        LicenseRef-undecided
URL:            https://github.com/MacGuard/macguard-yara-channel
Source0:        mgctl-%{version}.tar.gz
BuildArch:      noarch
Requires:       python3 >= 3.9

%description
Front end that delegates to the MacGuard engines. The short alias mg is never created.

%prep
%setup -q -n mgctl-%{version}

%install
install -d %{buildroot}%{_prefix}/lib/mgctl/bin %{buildroot}%{_bindir}
cp -R mgctl intel config scripts %{buildroot}%{_prefix}/lib/mgctl/
install -m 0755 bin/mgctl %{buildroot}%{_prefix}/lib/mgctl/bin/mgctl
ln -s ../lib/mgctl/bin/mgctl %{buildroot}%{_bindir}/mgctl

%files
%{_bindir}/mgctl
%{_prefix}/lib/mgctl
%doc docs/mgctl.md docs/mgctl-install.md

%changelog
* Thu Oct 22 2026 MacGuard <noreply@invalid.example> - 0.1.0-1
- Template only.
