package gateway

import (
	"mime"
	"net/mail"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/emersion/go-message/charset"
	"github.com/emersion/go-message/textproto"
	"golang.org/x/text/unicode/norm"
)

type headerProjection struct {
	property, name, form string
	all                  bool
}

func (args *getArgs) prepareHeaderProjections() bool {
	var valid bool
	args.headerFields, valid = compileHeaderProjections(args.Properties)
	if !valid {
		return false
	}
	args.bodyHeaderFields, valid = compileHeaderProjections(args.BodyProperties)
	return valid
}

func headerProjectionOnly(properties []string) bool {
	for _, property := range properties {
		if property != "headers" && !strings.HasPrefix(property, "header:") && !metaOnly([]string{property}) {
			return false
		}
	}
	return true
}

var namedEmailHeaders = []headerProjection{
	{property: "sentAt", name: "date", form: "asDate"},
	{property: "subject", name: "subject", form: "asText"},
	{property: "messageId", name: "message-id", form: "asMessageIds"},
	{property: "inReplyTo", name: "in-reply-to", form: "asMessageIds"},
	{property: "references", name: "references", form: "asMessageIds"},
	{property: "from", name: "from", form: "asAddresses"},
	{property: "sender", name: "sender", form: "asAddresses"},
	{property: "to", name: "to", form: "asAddresses"},
	{property: "cc", name: "cc", form: "asAddresses"},
	{property: "bcc", name: "bcc", form: "asAddresses"},
	{property: "replyTo", name: "reply-to", form: "asAddresses"},
}

func lastHeaderValue(header textproto.Header, name string) string {
	values := header.Values(name)
	if len(values) == 0 {
		return ""
	}
	return values[len(values)-1]
}

var knownHeaderForms = map[string]string{
	"return-path": "", "received": "",
	"subject": "asText", "list-id": "asText", "comments": "asText", "keywords": "asText",
	"from": "asAddresses", "sender": "asAddresses", "reply-to": "asAddresses", "to": "asAddresses", "cc": "asAddresses", "bcc": "asAddresses",
	"resent-from": "asAddresses", "resent-sender": "asAddresses", "resent-reply-to": "asAddresses", "resent-to": "asAddresses", "resent-cc": "asAddresses", "resent-bcc": "asAddresses",
	"message-id": "asMessageIds", "references": "asMessageIds", "in-reply-to": "asMessageIds", "resent-message-id": "asMessageIds",
	"date": "asDate", "resent-date": "asDate",
	"list-help": "asURLs", "list-unsubscribe": "asURLs", "list-subscribe": "asURLs", "list-post": "asURLs", "list-owner": "asURLs", "list-archive": "asURLs",
}

func compileHeaderProjections(properties []string) ([]headerProjection, bool) {
	var projections []headerProjection
	for _, property := range properties {
		selector, ok := strings.CutPrefix(property, "header:")
		if !ok {
			continue
		}
		fields := strings.Split(selector, ":")
		name := strings.ToLower(fields[0])
		if name == "" || strings.IndexFunc(fields[0], func(r rune) bool { return r < 33 || r > 126 }) >= 0 {
			return nil, false
		}
		fields = fields[1:]
		p := headerProjection{property: property, name: name, form: "asRaw"}
		if len(fields) > 0 && fields[len(fields)-1] == "all" {
			p.all = true
			fields = fields[:len(fields)-1]
		}
		if len(fields) > 1 {
			return nil, false
		}
		if len(fields) == 1 {
			p.form = fields[0]
		}
		switch p.form {
		case "asRaw", "asText", "asAddresses", "asGroupedAddresses", "asMessageIds", "asDate", "asURLs":
		default:
			return nil, false
		}
		if required, known := knownHeaderForms[name]; known && p.form != "asRaw" && p.form != required &&
			!(required == "asAddresses" && p.form == "asGroupedAddresses") {
			return nil, false
		}
		projections = append(projections, p)
	}
	return projections, true
}

func renderHeaderProjections(record object, headers []object, projections []headerProjection) {
	if len(projections) == 0 {
		return
	}
	byName := make(map[string][]string)
	for _, field := range headers {
		name := strings.ToLower(field["name"].(string))
		byName[name] = append(byName[name], field["value"].(string))
	}
	for _, p := range projections {
		values := byName[p.name]
		if p.all {
			parsed := make([]any, 0, len(values))
			for _, value := range values {
				parsed = append(parsed, parseHeaderForm(value, p.form))
			}
			record[p.property] = parsed
		} else if len(values) == 0 {
			record[p.property] = nil
		} else {
			record[p.property] = parseHeaderForm(values[len(values)-1], p.form)
		}
	}
}

func parseHeaderForm(raw, form string) any {
	if form == "asRaw" {
		return raw
	}
	value := strings.NewReplacer("\r\n", "", "\n", "").Replace(raw)
	switch form {
	case "asText":
		return headerTextForm(strings.TrimLeft(value, " "))
	case "asAddresses":
		return headerAddresses(value)
	case "asGroupedAddresses":
		return parseHeaderAddressGroups(value)
	case "asMessageIds":
		return parseHeaderAngles(value, false)
	case "asDate":
		if date, err := mail.ParseDate(value); err == nil {
			return date.Format(time.RFC3339)
		}
	default: // asURLs
		return parseHeaderAngles(value, true)
	}
	return nil
}

var encodedHeaderWord = regexp.MustCompile(`=\?[^?\s]+\?[bBqQ]\?[^?\s]+\?=`)

func headerTextForm(value string) string {
	decoder := mime.WordDecoder{CharsetReader: charset.Reader}
	var out strings.Builder
	previous := 0
	for _, match := range encodedHeaderWord.FindAllStringIndex(value, -1) {
		start, end := match[0], match[1]
		if start > 0 && !isHeaderWhitespace(value[start-1]) || end < len(value) && !isHeaderWhitespace(value[end]) {
			continue
		}
		if gap := value[previous:start]; previous == 0 || strings.Trim(gap, " \t") != "" {
			out.WriteString(gap)
		}
		decoded, err := decoder.Decode(value[start:end])
		if err != nil {
			decoded = "\uFFFD"
		}
		out.WriteString(strings.Map(func(r rune) rune {
			if unicode.IsControl(r) {
				return -1
			}
			return r
		}, decoded))
		previous = end
	}
	out.WriteString(value[previous:])
	return norm.NFC.String(strings.ToValidUTF8(out.String(), "\uFFFD"))
}

func isHeaderWhitespace(b byte) bool { return b == ' ' || b == '\t' }
