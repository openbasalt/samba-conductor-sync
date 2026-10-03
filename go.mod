module github.com/openbasalt/samba-conductor-sync

go 1.27.0

// Sibling modules of the Samba Conductor family are pinned by commit
// (pseudo-versions until they are tagged). A go.work in the family
// directory overrides the pins for local development (CONTRIBUTING.md).

require (
	github.com/BurntSushi/toml v1.6.0
	github.com/go-ldap/ldap/v3 v3.4.14
	github.com/openbasalt/samba-conductor-ad v0.0.0-20261003144929-e3e142131ee5
	modernc.org/sqlite v1.60.1
)

require (
	github.com/Azure/go-ntlmssp v0.1.1 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.8 // indirect
	github.com/go-crypt/x v0.4.12 // indirect
	github.com/go-krb5/krb5 v0.1.0 // indirect
	github.com/go-krb5/x v0.3.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	modernc.org/libc v1.77.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)
