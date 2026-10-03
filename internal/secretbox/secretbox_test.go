package secretbox

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func TestSealOpen(t *testing.T) {
	key := bytes.Repeat([]byte{7}, KeySize)
	for _, form := range [][]byte{key, []byte(hex.EncodeToString(key) + "\n"), []byte("BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=")} {
		b, err := New(form)
		if err != nil {
			t.Fatalf("key form %q: %v", form, err)
		}
		n, c, err := b.Seal("google-key", []byte("secret"))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(c, []byte("secret")) {
			t.Fatal("plaintext in ciphertext")
		}
		if got, err := b.Open("google-key", n, c); err != nil || string(got) != "secret" {
			t.Fatalf("open: %q %v", got, err)
		}
		if _, err := b.Open("other-name", n, c); !errors.Is(err, ErrDecrypt) {
			t.Fatal("name not bound")
		}
		c[0] ^= 1
		if _, err := b.Open("google-key", n, c); !errors.Is(err, ErrDecrypt) {
			t.Fatal("tampering not detected")
		}
	}
	other, _ := New(bytes.Repeat([]byte{8}, KeySize))
	b, _ := New(key)
	n, c, _ := b.Seal("x", []byte("v"))
	if _, err := other.Open("x", n, c); !errors.Is(err, ErrDecrypt) {
		t.Fatal("wrong key opened")
	}
	if _, err := New([]byte("short")); err == nil {
		t.Fatal("short key accepted")
	}
}
