package gateway

import (
	"net/mail"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

func validAddress(value string) bool {
	_, ok := smtpAddressKey(value)
	return ok
}

// smtpAddressKey validates the supported dot-atom mailbox form. The local part
// remains byte- and case-sensitive. Only the DNS domain is canonicalized.
func smtpAddressKey(value string) (string, bool) {
	if len(value) > 254 || !utf8.ValidString(value) || strings.IndexFunc(value, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r) || strings.ContainsRune("<>()[],:;\\\"", r) ||
			r >= 0xfdd0 && r <= 0xfdef || r&0xffff >= 0xfffe
	}) >= 0 {
		return "", false
	}
	at := strings.LastIndexByte(value, '@')
	if at <= 0 || at > 64 || at == len(value)-1 {
		return "", false
	}
	mailbox, err := mail.ParseAddress(value)
	if err != nil || mailbox.Name != "" || mailbox.Address != value {
		return "", false
	}
	domain, err := idna.Lookup.ToASCII(value[at+1:])
	if err != nil || len(domain) == 0 || len(domain) > 253 ||
		strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") || strings.Contains(domain, "..") {
		return "", false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
	}
	return value[:at+1] + strings.ToLower(domain), true
}
