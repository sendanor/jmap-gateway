package gateway

import (
	"encoding/base64"
	"encoding/json"
	"mime"
	"net/mail"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/emersion/go-message/charset"
)

type draftHeader struct {
	name, value string // value starts immediately after the colon
}

func draftHeaders(fields rawObject, now time.Time, allowsFrom func(string) bool) ([]draftHeader, object) {
	keys := sortedKeys(fields)
	selectors, ok := compileHeaderProjections(keys)
	if !ok {
		return nil, invalidDraft()
	}
	byProperty := make(map[string]headerProjection, len(selectors)+len(namedEmailHeaders))
	for _, selector := range selectors {
		byProperty[selector.property] = selector
	}
	for _, selector := range namedEmailHeaders {
		byProperty[selector.property] = selector
	}

	var headers []draftHeader
	claimed := make(map[string]bool)
	emitted := make(map[string]bool)
	addressCount := 0
	for _, key := range keys {
		p, found := byProperty[key]
		if !found {
			continue
		}
		data := fields[key]
		delete(fields, key)
		if claimed[p.name] || strings.HasPrefix(p.name, "content-") {
			return nil, invalidProperty(key)
		}
		claimed[p.name] = true
		values, valid := draftHeaderValues(p, data)
		if !valid {
			return nil, invalidProperty(key)
		}
		for _, header := range values {
			wire := header.value
			switch p.name {
			case "from", "sender":
				parser := mail.AddressParser{WordDecoder: &mime.WordDecoder{CharsetReader: charset.Reader}}
				addresses, err := parser.ParseList(unfoldDraftHeader(wire))
				if len(values) != 1 || err != nil || len(addresses) != 1 || !allowsFrom(addresses[0].Address) {
					return nil, invalidProperty(key)
				}
			case "mime-version":
				if p.form != "asRaw" || len(values) != 1 || strings.TrimSpace(unfoldDraftHeader(wire)) != "1.0" {
					return nil, invalidProperty(key)
				}
			case "to", "cc", "bcc":
				addressCount += len(headerAddresses(unfoldDraftHeader(wire)))
			}
			headers = append(headers, header)
			emitted[p.name] = true
		}
	}
	if addressCount > maxSubmissionRecipients {
		return nil, invalidDraft()
	}
	if !emitted["date"] {
		headers = append(headers, draftHeader{"date", " " + now.Format(time.RFC1123Z)})
	}
	if !emitted["message-id"] {
		headers = append(headers, draftHeader{"message-id", " <" + randomID() + "@jmap.invalid>"})
	}
	if !emitted["mime-version"] {
		headers = append(headers, draftHeader{"mime-version", " 1.0"})
	}
	return headers, nil
}

func draftHeaderValues(p headerProjection, data json.RawMessage) ([]draftHeader, bool) {
	if string(data) == "null" {
		return nil, true
	}
	values := []json.RawMessage{data}
	if p.all && !decodeStrict(data, &values) {
		return nil, false
	}
	headers := make([]draftHeader, 0, len(values))
	for _, value := range values {
		wire, valid := encodeDraftHeader(p, value)
		if !valid || !validDraftWireHeader(p.name, wire) {
			return nil, false
		}
		headers = append(headers, draftHeader{p.name, wire})
	}
	return headers, true
}

func encodeDraftHeader(p headerProjection, raw json.RawMessage) (string, bool) {
	switch p.form {
	case "asRaw", "asText", "asDate":
		var value *string
		if !decodeStrict(raw, &value) || value == nil {
			return "", false
		}
		switch p.form {
		case "asRaw":
			return *value, true
		case "asText":
			if !safeDraftHeader(*value, 512) {
				return "", false
			}
			return encodeDraftText(*value), true
		default:
			date, err := time.Parse(time.RFC3339, *value)
			if err != nil || date.Year() < 1900 {
				return "", false
			}
			return " " + date.Format(time.RFC1123Z), true
		}
	case "asAddresses":
		var values []address
		if !decodeStrict(raw, &values) || values == nil {
			return "", false
		}
		return encodeDraftAddresses(values)
	case "asGroupedAddresses":
		var groups []emailAddressGroup
		if !decodeStrict(raw, &groups) || groups == nil {
			return "", false
		}
		return encodeDraftGroups(groups)
	default: // asMessageIds or asURLs
		var values []string
		if !decodeStrict(raw, &values) || len(values) == 0 || len(values) > maxSubmissionRecipients {
			return "", false
		}
		for i, value := range values {
			if !draftASCIIToken(value) || strings.ContainsAny(value, "<>") {
				return "", false
			}
			if p.form == "asMessageIds" {
				if !validMessageID(value) {
					return "", false
				}
			} else {
				uri, err := url.Parse(value)
				if err != nil || uri.Scheme == "" {
					return "", false
				}
			}
			values[i] = "<" + value + ">"
		}
		separator := "\r\n "
		if p.form == "asURLs" {
			separator = ",\r\n "
		}
		return " " + strings.Join(values, separator), true
	}
}

func encodeDraftText(value string) string {
	if !strings.HasPrefix(value, " ") && !encodedHeaderWord.MatchString(value) &&
		strings.IndexFunc(value, func(r rune) bool { return r > 127 }) < 0 {
		return " " + value
	}
	// RFC 2047 limits each encoded word to 75 characters. Chunk at UTF-8
	// boundaries and fold between words so the decoder can join them.
	var words []string
	for len(value) != 0 {
		n := min(len(value), 45)
		for n < len(value) && !utf8.RuneStart(value[n]) {
			n--
		}
		words = append(words, "=?UTF-8?B?"+base64.StdEncoding.EncodeToString([]byte(value[:n]))+"?=")
		value = value[n:]
	}
	return " " + strings.Join(words, "\r\n ")
}

func encodeDraftAddresses(values []address) (string, bool) {
	if len(values) > maxSubmissionRecipients {
		return "", false
	}
	parts := make([]string, 0, len(values))
	for _, item := range values {
		if !validAddress(item.Email) || item.Name != nil && !safeDraftHeader(*item.Name, 200) {
			return "", false
		}
		parts = append(parts, addressHeader(item))
	}
	return " " + strings.Join(parts, ",\r\n "), true
}

func encodeDraftGroups(groups []emailAddressGroup) (string, bool) {
	if len(groups) > maxSubmissionRecipients {
		return "", false
	}
	parts := make([]string, 0, len(groups))
	for _, group := range groups {
		encoded, valid := encodeDraftAddresses(group.Addresses)
		if !valid || group.Addresses == nil {
			return "", false
		}
		if group.Name == nil {
			if len(group.Addresses) != 0 {
				parts = append(parts, strings.TrimPrefix(encoded, " "))
			}
			continue
		}
		if *group.Name == "" || !safeDraftHeader(*group.Name, 200) {
			return "", false
		}
		// Format the group name with the same quoted/encoded phrase rules
		// as a mailbox display name, then remove the placeholder address.
		phrase := addressHeader(address{Name: group.Name, Email: "group@invalid"})
		phrase = strings.TrimSuffix(phrase, " <group@invalid>")
		parts = append(parts, phrase+":"+encoded+";")
	}
	return " " + strings.Join(parts, ",\r\n "), true
}

func unfoldDraftHeader(value string) string { return strings.ReplaceAll(value, "\r\n", "") }

func validDraftWireHeader(name, value string) bool {
	lines := strings.Split(value, "\r\n")
	if len(name)+1+len(lines[0]) > 998 {
		return false
	}
	for i, line := range lines {
		if len(line) > 998 || strings.IndexFunc(line, func(r rune) bool { return r != '\t' && unicode.IsControl(r) }) >= 0 {
			return false
		}
		if i > 0 && (line == "" || !isHeaderWhitespace(line[0])) {
			return false
		}
	}
	return true
}
