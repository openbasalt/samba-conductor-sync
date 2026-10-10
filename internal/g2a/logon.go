package g2a

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/openbasalt/samba-conductor-ad/escape"
)

// Logon names follow the rules of the one-time import from Google
// (docs/import-from-google.md, "Logon names"), unchanged: the local part
// of the address in lower case when it is a valid sAMAccountName as it is
// and free, else the rendered fallback template; accents folded to ASCII,
// other characters dropped, at most 20 characters; never an invented
// numbered name. conductor applies the same rules in its import; these
// functions are a copy of them and must stay identical.

// DefaultLogonTemplate renders a logon name when the address's local part
// cannot be one (too long, invalid characters) or is taken.
const DefaultLogonTemplate = "{given}.{family}"

// maxUserSAM bounds sAMAccountName (the pre-Windows 2000 limit) and maxCN
// the common name.
const (
	maxUserSAM = 20
	maxCN      = 64
)

// ValidLogonTemplate checks a logon name template: at least one
// placeholder, only known placeholders, and only characters a logon name
// may hold.
func ValidLogonTemplate(tmpl string) bool {
	if tmpl == "" || len(tmpl) > 64 {
		return false
	}
	rest := tmpl
	placeholders := 0
	for _, p := range []string{"{given}", "{family}", "{g}", "{f}", "{local}"} {
		placeholders += strings.Count(rest, p)
		rest = strings.ReplaceAll(rest, p, "")
	}
	if placeholders == 0 {
		return false
	}
	for _, r := range rest {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// foldTable maps the accented Latin letters names commonly carry to ASCII.
var foldTable = map[rune]string{
	'à': "a", 'á': "a", 'â': "a", 'ã': "a", 'ä': "a", 'å': "a", 'ā': "a", 'ă': "a", 'ą': "a",
	'ç': "c", 'ć': "c", 'č': "c", 'ď': "d", 'đ': "d",
	'è': "e", 'é': "e", 'ê': "e", 'ë': "e", 'ē': "e", 'ė': "e", 'ę': "e", 'ě': "e",
	'ì': "i", 'í': "i", 'î': "i", 'ï': "i", 'ī': "i", 'į': "i", 'ı': "i",
	'ñ': "n", 'ń': "n", 'ň': "n", 'ł': "l", 'ľ': "l",
	'ò': "o", 'ó': "o", 'ô': "o", 'õ': "o", 'ö': "o", 'ø': "o", 'ō': "o", 'ő': "o",
	'ř': "r", 'ś': "s", 'š': "s", 'ş': "s", 'ť': "t", 'ţ': "t",
	'ù': "u", 'ú': "u", 'û': "u", 'ü': "u", 'ū': "u", 'ů': "u", 'ű': "u", 'ų': "u",
	'ý': "y", 'ÿ': "y", 'ź': "z", 'ż': "z", 'ž': "z",
	'ß': "ss", 'æ': "ae", 'œ': "oe", 'þ': "th", 'ð': "d",
}

// logonName folds text into a logon name: lower-case ASCII letters,
// digits, '.', '-' and '_'; other characters are dropped (spaces become
// nothing), repeated dots collapse, leading and trailing dots and hyphens
// go, and the result is cut to max characters.
func logonName(s string, max int) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			if f, ok := foldTable[r]; ok {
				b.WriteString(f)
			}
		}
	}
	out := b.String()
	for strings.Contains(out, "..") {
		out = strings.ReplaceAll(out, "..", ".")
	}
	out = strings.Trim(out, ".-")
	if len(out) > max {
		out = strings.TrimRight(out[:max], ".-")
	}
	return out
}

// validLogon reports whether s may be used as is as a sAMAccountName
// (the ad library's rules, plus no spaces in derived names).
func validLogon(s string, max int) bool {
	if s == "" || utf8.RuneCountInString(s) > max || strings.HasSuffix(s, ".") {
		return false
	}
	return !strings.ContainsFunc(s, func(r rune) bool {
		return r < 0x21 || r == 0x7f || strings.ContainsRune(`"/\[]:;|=,+*?<>@`, r) || unicode.IsSpace(r)
	})
}

func localPart(email string) string {
	if i := strings.LastIndexByte(email, '@'); i > 0 {
		return email[:i]
	}
	return email
}

func firstLetter(s string) string {
	for _, r := range logonName(s, 64) {
		return string(r)
	}
	return ""
}

// renderFallback renders the fallback template for a user.
func renderFallback(tmpl, given, family, email string) string {
	r := strings.NewReplacer("{given}", logonName(given, 64), "{family}", logonName(lastWord(family), 64),
		"{g}", firstLetter(given), "{f}", firstLetter(lastWord(family)), "{local}", logonName(localPart(email), 64))
	return logonName(r.Replace(tmpl), maxUserSAM)
}

// lastWord is the last word of a family name ("da Silva" -> "Silva").
func lastWord(s string) string {
	f := strings.Fields(s)
	if len(f) == 0 {
		return ""
	}
	return f[len(f)-1]
}

// LogonCandidates are the logon names tried for a user, in order: the
// local part of the address when it is a valid logon name as is (lower
// case), then the fallback.
func LogonCandidates(fallback, given, family, email string) []string {
	var out []string
	if lp := strings.ToLower(localPart(email)); validLogon(lp, maxUserSAM) {
		out = append(out, lp)
	}
	if fb := renderFallback(fallback, given, family, email); validLogon(fb, maxUserSAM) && !contains(out, fb) {
		out = append(out, fb)
	}
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// cutRunes cuts s to n characters.
func cutRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return strings.TrimSpace(string([]rune(s)[:n]))
}

// CNKey is the key of a common name in an OU (TakenCN).
func CNKey(parent, cn string) string { return escape.NormalizeDN(parent) + "|" + strings.ToLower(cn) }
