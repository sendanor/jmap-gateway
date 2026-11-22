package gateway

import (
	"mime"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/emersion/go-message/charset"
	"github.com/emersion/go-message/textproto"
)

type emailSortHeaders struct {
	from, to, subject string
	sentAt            time.Time
	hasSentAt         bool
}

func sortHeaders(header textproto.Header) emailSortHeaders {
	sentAt, err := mail.ParseDate(lastHeaderValue(header, "Date"))
	return emailSortHeaders{
		from:    firstAddressSortValue(headerAddresses(lastHeaderValue(header, "From"))),
		to:      firstAddressSortValue(headerAddresses(lastHeaderValue(header, "To"))),
		subject: baseSubject(lastHeaderValue(header, "Subject")), sentAt: sentAt, hasSentAt: err == nil,
	}
}

func compareSortHeaders(a, b emailSortHeaders, property string, compareText func(string, string) int) int {
	switch property {
	case "from":
		return compareText(a.from, b.from)
	case "to":
		return compareText(a.to, b.to)
	case "subject":
		return compareText(a.subject, b.subject)
	default:
		if a.hasSentAt != b.hasSentAt {
			return queryBool(a.hasSentAt) - queryBool(b.hasSentAt)
		}
		return a.sentAt.Compare(b.sentAt)
	}
}

func firstAddressSortValue(list []address) string {
	if len(list) == 0 {
		return ""
	}
	if list[0].Name == nil || *list[0].Name == "" {
		return list[0].Email
	}
	return *list[0].Name
}

var subjectBlob = regexp.MustCompile(`^\[[^\[\]\x00]*\] *`)
var subjectRefwd = regexp.MustCompile(`(?i)^(?:re|fwd?) *(?:\[[^\[\]\x00]*\] *)?:`)

// baseSubject applies the ordered stripping steps from RFC 5256 §2.1.
// Thread assignment uses its own subject matching rules and stays independent.
func baseSubject(subject string) string {
	decoder := &mime.WordDecoder{CharsetReader: charset.Reader}
	if decoded, err := decoder.DecodeHeader(subject); err == nil {
		subject = decoded
	}
	subject = strings.Join(strings.FieldsFunc(subject, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\r' || r == '\n'
	}), " ")
	for {
		for len(subject) >= 5 && strings.EqualFold(subject[len(subject)-5:], "(fwd)") {
			subject = strings.TrimRight(subject[:len(subject)-5], " ")
		}
		for {
			if leader := subjectRefwd.FindStringIndex(subject); leader != nil {
				subject = strings.TrimLeft(subject[leader[1]:], " ")
				continue
			}
			if blob := subjectBlob.FindStringIndex(subject); blob != nil && blob[1] < len(subject) {
				subject = subject[blob[1]:]
				continue
			}
			break
		}
		if len(subject) < 6 || !strings.EqualFold(subject[:5], "[fwd:") || subject[len(subject)-1] != ']' {
			return subject
		}
		subject = strings.Trim(subject[5:len(subject)-1], " ")
	}
}
