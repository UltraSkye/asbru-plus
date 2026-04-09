%define _bashcompletiondir %(pkg-config --variable=completionsdir bash-completion)

Name:       asbru-plus
Version:    %{_version}
Release:    %{_release}%{?dist}
Summary:    A free and open-source SSH/RDP/VNC connection manager (fork of Asbrú CM)
License:    GPLv3+
URL:        https://github.com/UltraSkye/asbru-plus
Source0:    https://github.com/UltraSkye/asbru-plus/archive/%{version}.tar.gz
BuildArch:  noarch
Autoreq:    no
Obsoletes:  asbru-cm
Requires:   perl
Requires:   perl(Carp)
Requires:   perl(Compress::Raw::Zlib)
Requires:   perl(Crypt::Blowfish)
Requires:   perl(Data::Dumper)
Requires:   perl(Digest::SHA)
Requires:   perl(DynaLoader)
Requires:   perl(Encode)
Requires:   perl(Expect)
Requires:   perl(Exporter)
Requires:   perl(File::Basename)
Requires:   perl(File::Copy)
Requires:   perl(FindBin)
Requires:   perl(Gtk3)
Requires:   perl(Gtk3::SimpleList)
Requires:   perl(IO::Handle)
Requires:   perl(IO::Socket)
Requires:   perl(IO::Socket::INET)
Requires:   perl(MIME::Base64)
Requires:   perl(Net::ARP)
Requires:   perl(Net::Ping)
Requires:   perl(UUID::Tiny)
Requires:   perl(POSIX)
Requires:   perl(Socket)
Requires:   perl(Socket6)
Requires:   perl(Storable)
Requires:   perl(Sys::Hostname)
Requires:   perl(Time::HiRes)
Requires:   perl(XML::Parser)
Requires:   perl(YAML)
Requires:   perl(constant)
Requires:   perl(lib)
Requires:   perl(strict)
Requires:   perl(utf8)
Requires:   perl(vars)
Requires:   perl(warnings)
Requires:   vte291
Requires:   bash
Requires:   perl-Crypt-CBC
Requires:   perl-Crypt-Rijndael
Requires:   perl-IO-Tty
Requires:   perl-IO-Stty
Requires:   libwnck3
Requires:   nmap-ncat
Recommends: keepassxc
Suggests:   freerdp or rdesktop
Suggests:   tigervnc or tightvnc
Suggests:   mosh
Suggests:   cu
Suggests:   telnet
Suggests:   ftp
Suggests:   perl-X11-GUITest
Suggests:   putty
BuildRequires: pkgconfig
BuildRequires: bash-completion
BuildRequires: desktop-file-utils
BuildRoot:  %{_topdir}/tmp/%{name}-%{version}-%{release}-root

%description
Ásbrú Plus is a community-maintained fork of Ásbrú Connection Manager.
It provides a graphical interface for organizing and automating remote
terminal sessions over SSH, RDP, VNC, Telnet and SFTP.
Targets Ubuntu 24.04+ and modern Fedora/EL systems.

%prep
%autosetup -n asbru-plus-%{version} -p1
sed -ri -e "s|\\\$RealBin[ ]*\.[ ]*'|'%{_datadir}/%{name}/lib|g" lib/asbru_conn
sed -ri -e "s|\\\$RealBin,|'%{_datadir}/%{name}/lib',|g" lib/asbru_conn
sed -ri -e "s|\\\$RealBin/\.\./|%{_datadir}/%{name}/|g" lib/asbru_conn
sed -ri -e "s|\\\$RealBin/|%{_datadir}/%{name}/lib/|g" lib/asbru_conn
find . -not -path './utils/*' -type f -exec sed -i \
  -e "s|\$RealBin[ ]*\.[ ]*'|'%{_datadir}/%{name}|g" \
  -e 's|"\$RealBin/|"%{_datadir}/%{name}/|g' \
  -e 's|/\.\.\(/\)|\1|' \
  '{}' \+


%build


%check
desktop-file-validate res/asbru-cm.desktop


%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/{%{_mandir}/man1,%{_bindir}}
mkdir -p %{buildroot}/%{_datadir}/{%{name}/{lib,res,utils},applications}
mkdir -p %{buildroot}/%{_bashcompletiondir}
mkdir -p %{buildroot}/%{_datadir}/icons/hicolor/{24x24,64x64,256x256,scalable}/apps
mkdir -p %{buildroot}/%{_datadir}/metainfo

install -m 755 asbru-cm %{buildroot}/%{_bindir}/%{name}

cp -a res/asbru-cm.desktop %{buildroot}/%{_datadir}/applications/%{name}.desktop
cp -a res/asbru-cm.1 %{buildroot}/%{_mandir}/man1/%{name}.1
cp -a res/asbru_bash_completion %{buildroot}/%{_bashcompletiondir}/%{name}

cp -a res/asbru-logo-24.png %{buildroot}/%{_datadir}/icons/hicolor/24x24/apps/%{name}.png
cp -a res/asbru-logo-64.png %{buildroot}/%{_datadir}/icons/hicolor/64x64/apps/%{name}.png
cp -a res/asbru-logo-256.png %{buildroot}/%{_datadir}/icons/hicolor/256x256/apps/%{name}.png
cp -a res/asbru-logo.svg %{buildroot}/%{_datadir}/icons/hicolor/scalable/apps/%{name}.svg

cp -a res/org.asbru.cm.appdata.xml %{buildroot}/%{_datadir}/metainfo/
cp -a res/*.{png,pl,glade,svg} %{buildroot}/%{_datadir}/%{name}/res/
cp -ar res/themes/ %{buildroot}/%{_datadir}/%{name}/res/
cp -a lib/* %{buildroot}/%{_datadir}/%{name}/lib/
cp -a utils/*.pl %{buildroot}/%{_datadir}/%{name}/utils/

%files
%doc README.md
%license LICENSE
%{_mandir}/man1/%{name}*
%{_datadir}/%{name}/
%{_datadir}/applications/%{name}.desktop
%{_datadir}/icons/hicolor/*/apps/%{name}.*
%{_bashcompletiondir}/%{name}*
%{_bindir}/%{name}*
%{_datadir}/metainfo/org.asbru.cm.appdata.xml


%post
/bin/touch --no-create %{_datadir}/icons/hicolor &>/dev/null || :


%postun
if [ $1 -eq 0 ] ; then
    /bin/touch --no-create %{_datadir}/icons/hicolor &>/dev/null
    /usr/bin/gtk-update-icon-cache %{_datadir}/icons/hicolor &>/dev/null || :
fi


%posttrans
/usr/bin/gtk-update-icon-cache %{_datadir}/icons/hicolor &>/dev/null || :


%changelog
* Wed Apr 09 2026 DemonSkye <31297354+UltraSkye@users.noreply.github.com> 6.5.0
- Fork as asbru-plus
- Security: comprehensive hardening (AES-256, master password, shell injection fixes)
- Security: HMAC config integrity, file locking, signal handler safety
- Fix keyboard shortcut modifier detection
- Fix telnet autologin CR/LF handling
- Fix RDP password special character escaping
- Fix jump host PreferredAuthentications override
- Fix session log always writing
- Fix known_hosts shell injection
- Fix proxy credentials in process list
- Fix readonly mode nstore crash
- Fix dangerous double-eval regex
* Sat Apr 04 2026 Ásbrú Project Team <contact@asbru-cm.net> 6.4.1
- 6.4.1 Release
* Sun Nov 13 2022 Ásbrú Project Team <contact@asbru-cm.net> 6.4.0
- 6.4.0 Release
