package passwd

import (
	"errors"
	"strings"
	"testing"
)

func TestGenerateSatisfiesRules(t *testing.T) {
	for _, r := range []Rules{
		{MinLength: 8, MaxLength: 100, PrintableASCII: true, NoEdgeSpaces: true},
		{MinLength: 12, MaxLength: 100, PrintableASCII: true},
		{MinLength: 30, MaxLength: 40},
	} {
		seen := map[string]bool{}
		for range 200 {
			pw, err := Generate(r)
			if err != nil {
				t.Fatal(err)
			}
			if err := Check(pw, r); err != nil {
				t.Fatalf("%q breaks %+v: %v", pw, r, err)
			}
			if !strings.ContainsAny(pw, "ABCDEFGHJKLMNPQRSTUVWXYZ") || !strings.ContainsAny(pw, "abcdefghijkmnpqrstuvwxyz") ||
				!strings.ContainsAny(pw, "23456789") {
				t.Fatalf("%q lacks a class", pw)
			}
			if strings.ContainsAny(pw, "0O1lI") {
				t.Fatalf("%q has an ambiguous character", pw)
			}
			if seen[pw] {
				t.Fatalf("repeated password %q", pw)
			}
			seen[pw] = true
		}
	}
	pw, _ := Generate(Rules{MinLength: 8, MaxLength: 100})
	if len(pw) != 19 || strings.Count(pw, "-") != 3 {
		t.Fatalf("format %q", pw)
	}
}

func TestGenerateRefusesImpossibleRules(t *testing.T) {
	if _, err := Generate(Rules{MinLength: 8, MaxLength: 10}); err == nil {
		t.Fatal("a password that cannot fit must be refused")
	}
}

func TestCheck(t *testing.T) {
	r := Rules{MinLength: 12, MaxLength: 20, PrintableASCII: true, NoEdgeSpaces: true}
	for pw, want := range map[string]string{
		"Xy7q":                     ProblemTooShort,
		"this one is far too long": ProblemTooLong,
		"senha-com-ção1":           ProblemCharacters,
		" leading space1":          ProblemEdgeSpaces,
		"tab\there-is-bad":         ProblemCharacters,
		"Good password 1":          "",
	} {
		err := Check(pw, r)
		var pe *Error
		switch {
		case want == "" && err != nil:
			t.Errorf("%q: %v", pw, err)
		case want != "" && (!errors.As(err, &pe) || pe.Problem != want):
			t.Errorf("%q: got %v, want %s", pw, err, want)
		case err != nil && strings.Contains(err.Error(), pw):
			t.Errorf("the error carries the password: %v", err)
		}
	}
}
