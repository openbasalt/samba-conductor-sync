// Package passwd generates and checks the passwords of the self-service
// actions (a user's own password on a target directory). A generated
// password is shown once to its user, who writes it down: it is made of
// groups of unambiguous letters and digits joined by hyphens, long enough
// for about 90 bits of entropy, and never contains characters that are hard
// to read or to type on a phone. Nothing here logs or keeps a password.
package passwd

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"unicode/utf8"
)

// Rules are what a password must satisfy (the target's own rules, raised by
// the self-service policy).
type Rules struct {
	MinLength, MaxLength int
	// PrintableASCII: only ASCII letters, digits, punctuation and spaces.
	PrintableASCII bool
	// NoEdgeSpaces: no space at the start or at the end.
	NoEdgeSpaces bool
}

// alphabet leaves out 0/O, 1/l/I and similar pairs.
const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"

const (
	groupLen = 4
	// minRandom is the least number of random characters (16 of 55
	// symbols: about 92 bits).
	minRandom = 16
)

// Generate returns a random password that satisfies r: groups of four
// characters joined by "-" ("Fh7q-k2Mx-9TzR-pa4N"), with at least one upper
// case letter, one lower case letter and one digit (strength rules of most
// targets).
func Generate(r Rules) (string, error) {
	n := minRandom
	// Each group adds 4 characters and a separator.
	for length(n) < r.MinLength {
		n += groupLen
	}
	if r.MaxLength > 0 && length(n) > r.MaxLength {
		return "", fmt.Errorf("passwd: no generated password fits %d-%d characters", r.MinLength, r.MaxLength)
	}
	for range 100 {
		var b strings.Builder
		for i := range n {
			if i > 0 && i%groupLen == 0 {
				b.WriteByte('-')
			}
			k, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
			if err != nil {
				return "", err
			}
			b.WriteByte(alphabet[k.Int64()])
		}
		pw := b.String()
		if strings.ContainsAny(pw, "ABCDEFGHJKLMNPQRSTUVWXYZ") && strings.ContainsAny(pw, "abcdefghijkmnpqrstuvwxyz") &&
			strings.ContainsAny(pw, "23456789") && Check(pw, r) == nil {
			return pw, nil
		}
	}
	return "", errors.New("passwd: could not generate a password")
}

// length is the length of a generated password with n random characters.
func length(n int) int { return n + (n-1)/groupLen }

// Problem codes of Check (stable, for translation by a client).
const (
	ProblemTooShort   = "too-short"
	ProblemTooLong    = "too-long"
	ProblemCharacters = "characters"
	ProblemEdgeSpaces = "edge-spaces"
)

// Error is a rule a password breaks. It never contains the password.
type Error struct {
	Problem string
	Rules   Rules
}

func (e *Error) Error() string {
	switch e.Problem {
	case ProblemTooShort:
		return fmt.Sprintf("the password is shorter than %d characters", e.Rules.MinLength)
	case ProblemTooLong:
		return fmt.Sprintf("the password is longer than %d characters", e.Rules.MaxLength)
	case ProblemCharacters:
		return "the password has characters the target does not accept (only ASCII letters, digits, punctuation and spaces)"
	case ProblemEdgeSpaces:
		return "the password starts or ends with a space"
	}
	return "the password breaks the target's rules"
}

// Check reports the first rule pw breaks (nil when it satisfies r).
func Check(pw string, r Rules) error {
	n := utf8.RuneCountInString(pw)
	switch {
	case !utf8.ValidString(pw):
		return &Error{Problem: ProblemCharacters, Rules: r}
	case n < r.MinLength:
		return &Error{Problem: ProblemTooShort, Rules: r}
	case r.MaxLength > 0 && n > r.MaxLength:
		return &Error{Problem: ProblemTooLong, Rules: r}
	}
	for _, c := range pw {
		if c < 0x20 || c == 0x7f || (r.PrintableASCII && c > 0x7e) {
			return &Error{Problem: ProblemCharacters, Rules: r}
		}
	}
	if r.NoEdgeSpaces && (strings.HasPrefix(pw, " ") || strings.HasSuffix(pw, " ")) {
		return &Error{Problem: ProblemEdgeSpaces, Rules: r}
	}
	return nil
}
