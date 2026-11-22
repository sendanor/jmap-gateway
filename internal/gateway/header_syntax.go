package gateway

import (
	"mime"
	"net/mail"
	"net/url"
	"strings"
	"unicode"

	"github.com/emersion/go-message/charset"
	"golang.org/x/text/unicode/norm"
)

type emailAddressGroup struct {
	Name      *string   `json:"name"`
	Addresses []address `json:"addresses"`
}

func headerAddresses(value string) []address {
	list := make([]address, 0)
	for _, group := range parseHeaderAddressGroups(value) {
		list = append(list, group.Addresses...)
	}
	return list
}

// The standard library validates individual mailboxes. This scanner retains
// their group boundaries while ignoring separators in quoted or escaped text.
func parseHeaderAddressGroups(value string) []emailAddressGroup {
	groups := []emailAddressGroup{}
	parser := mail.AddressParser{WordDecoder: &mime.WordDecoder{CharsetReader: charset.Reader}}
	inGroup := false
	var group emailAddressGroup
	add := func(raw string) {
		item, err := parser.Parse(raw)
		if err != nil {
			return
		}
		entry := address{Email: item.Address}
		if name := cleanAddressName(item.Name); name != "" {
			entry.Name = &name
		}
		if inGroup {
			group.Addresses = append(group.Addresses, entry)
		} else if last := len(groups) - 1; last >= 0 && groups[last].Name == nil {
			groups[last].Addresses = append(groups[last].Addresses, entry)
		} else {
			groups = append(groups, emailAddressGroup{Addresses: []address{entry}})
		}
	}
	start := 0
	var quoted, angle, literal bool
	for i := 0; i < len(value); i++ {
		b := value[i]
		switch {
		case b == '\\' && (quoted || literal):
			i++
		case b == '"' && !literal:
			quoted = !quoted
		case quoted:
		case b == '[':
			literal = true
		case b == ']':
			literal = false
		case literal:
		case b == '(':
			end := afterHeaderComment(value[i:])
			if end == 0 {
				i = len(value)
			} else {
				i += end - 1
			}
		case b == '<':
			angle = true
		case b == '>':
			angle = false
		case angle:
		case b == ':':
			label := strings.TrimSpace(value[start:i])
			if parsed, err := parser.Parse(label + " <group@invalid>"); err == nil && parsed.Name != "" {
				label = parsed.Name
			}
			label = cleanAddressName(label)
			group = emailAddressGroup{Name: &label, Addresses: []address{}}
			inGroup = true
			start = i + 1
		case b == ',' || b == ';':
			add(value[start:i])
			if b == ';' && inGroup {
				groups = append(groups, group)
				inGroup = false
			}
			start = i + 1
		}
	}
	add(value[start:])
	if inGroup {
		groups = append(groups, group)
	}
	return groups
}

func cleanAddressName(name string) string {
	return norm.NFC.String(strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, name)))
}

func afterHeaderComment(value string) int {
	depth := 0
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i + 1
			}
		case '\\':
			i++
		}
	}
	return 0
}

func skipHeaderCFWS(value string) string {
	for {
		value = strings.TrimLeft(value, " \t")
		if !strings.HasPrefix(value, "(") {
			return value
		}
		end := afterHeaderComment(value)
		if end == 0 {
			return value
		}
		value = value[end:]
	}
}

func parseHeaderAngles(value string, urls bool) []string {
	var result []string
	for rest := skipHeaderCFWS(value); rest != ""; rest = skipHeaderCFWS(rest) {
		item, tail, closed := strings.Cut(rest, ">")
		if !closed || !strings.HasPrefix(item, "<") {
			return nil
		}
		item = item[1:]
		if urls {
			// RFC 2369 permits whitespace inserted inside the angle brackets.
			item = strings.Join(strings.Fields(item), "")
			uri, err := url.Parse(item)
			if err != nil || uri.Scheme == "" {
				return nil
			}
		} else {
			mailbox, err := mail.ParseAddress(strings.TrimSpace(item))
			if err != nil || mailbox.Name != "" || strings.ContainsAny(item, "<>\r\n") {
				return nil
			}
			item = mailbox.Address
		}
		result = append(result, item)
		rest = skipHeaderCFWS(tail)
		if urls && rest != "" {
			if rest[0] != ',' || skipHeaderCFWS(rest[1:]) == "" {
				return nil
			}
			rest = rest[1:]
		}
	}
	return result
}
