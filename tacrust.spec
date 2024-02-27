Name:         tacrust
Version:      %{my_version}
Release:      %{my_iteration}.el9
BuildArch:    x86_64
Summary:      TACACS+ implementation in Rust
License:      Salesforce Proprietary Copyright
URL:          https://git.soma.salesforce.com/Kuleana/tacrust
Packager:     platform-integrity-c4ssh@salesforce.com

%description
TACACS+ implementation in Rust

%prep
# N/A

%build
# Done as part of build.sh in .strata.yaml.

%install
mkdir -p %{buildroot}/usr/bin

# bin
cp %{proj_path}/target/release/tacrustd %{buildroot}/usr/bin/tacrustd

%post

%files
/usr/bin/tacrustd

%changelog