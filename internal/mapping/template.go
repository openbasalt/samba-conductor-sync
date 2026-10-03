// Package mapping turns source directory entries into the target model:
// address and attribute templates, address validation against the allowed
// domains, and AD OU to target org unit placement.
//
// Template syntax: literal text with {attribute} or {attribute|filter|…}
// placeholders. Attribute names are LDAP attribute names (case-insensitive,
// e.g. sAMAccountName, userPrincipalName, givenName, sn, mail, cn).
// Filters: lower, upper, trim, localpart (before "@"), domain (after "@"),
// ascii (fold accents: "José" -> "Jose"), slug (lowercase ASCII letters,
// digits, ".", "_" and "-"; other runs become "-").
package mapping

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/openbasalt/samba-conductor-ad/escape"
)

// Template is a parsed template.
type Template struct {
	src   string
	parts []part
}

type part struct {
	literal string
	attr    string
	filters []string
}

var knownFilters = map[string]func(string) string{
	"lower":     strings.ToLower,
	"upper":     strings.ToUpper,
	"trim":      strings.TrimSpace,
	"localpart": func(s string) string { l, _, _ := strings.Cut(s, "@"); return l },
	"domain": func(s string) string {
		_, d, ok := strings.Cut(s, "@")
		if !ok {
			return ""
		}
		return d
	},
	"ascii": FoldASCII,
	"slug":  Slug,
}

// ParseTemplate parses one template.
func ParseTemplate(src string) (Template, error) {
	t := Template{src: src}
	rest := src
	for rest != "" {
		i := strings.IndexByte(rest, '{')
		j := strings.IndexByte(rest, '}')
		if j >= 0 && (i < 0 || j < i) {
			return t, fmt.Errorf("template %q: unmatched '}'", src)
		}
		if i < 0 {
			t.parts = append(t.parts, part{literal: rest})
			break
		}
		if i > 0 {
			t.parts = append(t.parts, part{literal: rest[:i]})
		}
		end := strings.IndexByte(rest[i:], '}')
		if end < 0 {
			return t, fmt.Errorf("template %q: unterminated '{'", src)
		}
		body := rest[i+1 : i+end]
		if strings.ContainsAny(body, "{") {
			return t, fmt.Errorf("template %q: nested '{'", src)
		}
		fields := strings.Split(body, "|")
		attr := strings.TrimSpace(fields[0])
		if !escape.ValidAttribute(attr) || strings.Contains(attr, ";") {
			return t, fmt.Errorf("template %q: invalid attribute %q", src, attr)
		}
		p := part{attr: attr}
		for _, f := range fields[1:] {
			f = strings.TrimSpace(f)
			if _, ok := knownFilters[f]; !ok {
				return t, fmt.Errorf("template %q: unknown filter %q", src, f)
			}
			p.filters = append(p.filters, f)
		}
		t.parts = append(t.parts, p)
		rest = rest[i+end+1:]
	}
	return t, nil
}

// MustParse parses or panics (tests and constants).
func MustParse(src string) Template {
	t, err := ParseTemplate(src)
	if err != nil {
		panic(err)
	}
	return t
}

// String returns the source text.
func (t Template) String() string { return t.src }

// Attributes lists the attributes the template reads.
func (t Template) Attributes() []string {
	var out []string
	for _, p := range t.parts {
		if p.attr != "" {
			out = append(out, p.attr)
		}
	}
	return out
}

// ErrMissing reports a placeholder whose attribute is empty.
var ErrMissing = errors.New("mapping: attribute empty")

// Attrs looks up attribute values case-insensitively.
type Attrs interface {
	Get(name string) string
}

// MapAttrs is an Attrs over a map keyed by lowercase attribute name.
type MapAttrs map[string]string

// Get implements Attrs.
func (m MapAttrs) Get(name string) string { return m[strings.ToLower(name)] }

// Render fills the template. A placeholder whose value (after filters) is
// empty yields ErrMissing, so a list of templates can fall back to the next.
func (t Template) Render(a Attrs) (string, error) {
	var sb strings.Builder
	for _, p := range t.parts {
		if p.attr == "" {
			sb.WriteString(p.literal)
			continue
		}
		v := a.Get(p.attr)
		for _, f := range p.filters {
			v = knownFilters[f](v)
		}
		if strings.TrimSpace(v) == "" {
			return "", fmt.Errorf("%w: %s", ErrMissing, p.attr)
		}
		sb.WriteString(v)
	}
	return strings.TrimSpace(sb.String()), nil
}

// RenderOptional renders and returns "" when an attribute is empty.
func (t Template) RenderOptional(a Attrs) string {
	v, err := t.Render(a)
	if err != nil {
		return ""
	}
	return v
}

// Chain is an ordered list of templates; the first that renders wins.
type Chain []Template

// ParseChain parses a list of templates.
func ParseChain(srcs []string) (Chain, error) {
	out := make(Chain, 0, len(srcs))
	for _, s := range srcs {
		t, err := ParseTemplate(s)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// Render returns the first value accepted by valid (nil accepts any
// non-empty value).
func (c Chain) Render(a Attrs, valid func(string) error) (string, error) {
	var errs []error
	for _, t := range c {
		v, err := t.Render(a)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if valid != nil {
			if err := valid(v); err != nil {
				errs = append(errs, err)
				continue
			}
		}
		return v, nil
	}
	if len(errs) == 0 {
		return "", errors.New("mapping: no template")
	}
	return "", errors.Join(errs...)
}

// Attributes lists every attribute read by the chain.
func (c Chain) Attributes() []string {
	var out []string
	for _, t := range c {
		out = append(out, t.Attributes()...)
	}
	return out
}

// fold maps common accented Latin letters to ASCII.
var fold = map[rune]string{
	'á': "a", 'à': "a", 'â': "a", 'ã': "a", 'ä': "a", 'å': "a", 'ā': "a", 'ă': "a", 'ą': "a",
	'Á': "A", 'À': "A", 'Â': "A", 'Ã': "A", 'Ä': "A", 'Å': "A", 'Ā': "A", 'Ă': "A", 'Ą': "A",
	'é': "e", 'è': "e", 'ê': "e", 'ë': "e", 'ē': "e", 'ė': "e", 'ę': "e", 'ě': "e",
	'É': "E", 'È': "E", 'Ê': "E", 'Ë': "E", 'Ē': "E", 'Ė': "E", 'Ę': "E", 'Ě': "E",
	'í': "i", 'ì': "i", 'î': "i", 'ï': "i", 'ī': "i", 'į': "i", 'ı': "i",
	'Í': "I", 'Ì': "I", 'Î': "I", 'Ï': "I", 'Ī': "I", 'Į': "I", 'İ': "I",
	'ó': "o", 'ò': "o", 'ô': "o", 'õ': "o", 'ö': "o", 'ø': "o", 'ō': "o", 'ő': "o",
	'Ó': "O", 'Ò': "O", 'Ô': "O", 'Õ': "O", 'Ö': "O", 'Ø': "O", 'Ō': "O", 'Ő': "O",
	'ú': "u", 'ù': "u", 'û': "u", 'ü': "u", 'ū': "u", 'ů': "u", 'ű': "u", 'ų': "u",
	'Ú': "U", 'Ù': "U", 'Û': "U", 'Ü': "U", 'Ū': "U", 'Ů': "U", 'Ű': "U", 'Ų': "U",
	'ç': "c", 'ć': "c", 'č': "c", 'Ç': "C", 'Ć': "C", 'Č': "C",
	'ñ': "n", 'ń': "n", 'ň': "n", 'Ñ': "N", 'Ń': "N", 'Ň': "N",
	'ý': "y", 'ÿ': "y", 'Ý': "Y", 'Ÿ': "Y",
	'ś': "s", 'š': "s", 'ş': "s", 'Ś': "S", 'Š': "S", 'Ş': "S",
	'ź': "z", 'ž': "z", 'ż': "z", 'Ź': "Z", 'Ž': "Z", 'Ż': "Z",
	'ł': "l", 'Ł': "L", 'đ': "d", 'Đ': "D", 'ď': "d", 'Ď': "D", 'ř': "r", 'Ř': "R", 'ť': "t", 'Ť': "T",
	'ß': "ss", 'æ': "ae", 'Æ': "AE", 'œ': "oe", 'Œ': "OE", 'þ': "th", 'Þ': "TH",
}

// FoldASCII replaces accented Latin letters with ASCII and drops any other
// non-ASCII character.
func FoldASCII(s string) string {
	var sb strings.Builder
	for _, r := range s {
		switch {
		case r < 0x80:
			sb.WriteRune(r)
		case fold[r] != "":
			sb.WriteString(fold[r])
		}
	}
	return sb.String()
}

// Slug lowercases, folds to ASCII and keeps [a-z0-9._-]; other runs become
// a single "-", trimmed at both ends.
func Slug(s string) string {
	s = strings.ToLower(FoldASCII(s))
	var sb strings.Builder
	dash := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			sb.WriteRune(r)
			dash = false
			continue
		}
		if !dash {
			sb.WriteByte('-')
			dash = true
		}
	}
	return strings.Trim(sb.String(), "-.")
}

// ValidateEmail accepts a plain ASCII address whose domain is one of the
// allowed domains (case-insensitive). The local part allows letters,
// digits and . _ - + ' (no leading, trailing or double dots).
func ValidateEmail(addr string, allowed []string) error {
	addr = strings.ToLower(strings.TrimSpace(addr))
	local, domain, ok := strings.Cut(addr, "@")
	if !ok || local == "" || domain == "" || strings.Contains(domain, "@") {
		return fmt.Errorf("mapping: %q is not an address", addr)
	}
	if len(local) > 64 || len(addr) > 254 {
		return fmt.Errorf("mapping: %q is too long", addr)
	}
	if strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") {
		return fmt.Errorf("mapping: %q has misplaced dots", addr)
	}
	for _, r := range local {
		if r > unicode.MaxASCII || !(unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("._-+'", r)) {
			return fmt.Errorf("mapping: %q has an invalid character %q", addr, r)
		}
	}
	for _, d := range allowed {
		if strings.EqualFold(strings.TrimSpace(d), domain) {
			return nil
		}
	}
	return fmt.Errorf("mapping: domain of %q is not in allowed_domains", addr)
}
