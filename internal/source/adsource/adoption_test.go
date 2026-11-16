package adsource

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/openbasalt/samba-conductor-ad/escape"
	"github.com/openbasalt/samba-conductor-ad/sid"
)

func TestAddressFilter(t *testing.T) {
	f, err := escape.Compile(addressFilter("a*b@x.com"))
	if err != nil {
		t.Fatal(err)
	}
	want := `(|(mail=a\2ab@x.com)(userPrincipalName=a\2ab@x.com)(proxyAddresses=smtp:a\2ab@x.com))`
	if f != want {
		t.Fatalf("%s != %s", f, want)
	}
}

func TestDuplicatesOf(t *testing.T) {
	self, _ := sid.ParseGUID("00000000-0000-4000-8000-000000000001")
	other, _ := sid.ParseGUID("00000000-0000-4000-8000-000000000002")
	entry := func(dn string, g sid.GUID) *ldap.Entry {
		e := ldap.NewEntry(dn, nil)
		e.Attributes = append(e.Attributes, &ldap.EntryAttribute{Name: "objectGUID", ByteValues: [][]byte{g.Bytes()}, Values: []string{string(g.Bytes())}})
		return e
	}
	got := duplicatesOf(self.String(), []*ldap.Entry{entry("CN=self", self), entry("CN=other", other)})
	if len(got) != 1 || got[0] != "CN=other" {
		t.Fatalf("duplicates %v", got)
	}
	if got := duplicatesOf(self.String(), []*ldap.Entry{entry("CN=self", self)}); len(got) != 0 {
		t.Fatalf("self counted: %v", got)
	}
}
