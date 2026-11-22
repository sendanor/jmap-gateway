package gateway

import (
	"bufio"
	"bytes"
	"encoding/json"
	"mime"
	nettextproto "net/textproto"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-message/charset"
	"github.com/emersion/go-message/textproto"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

type emailSearch struct {
	op        *operation
	needsMIME bool
	loaded    bool
	failure   string
	header    textproto.Header
	mime      *mimeMessage
	headers   map[string][]string
	body      []string
}

func (q *emailQuery) contentCondition(property string, input json.RawMessage) (func(*emailMeta) bool, string) {
	switch property {
	case "hasAttachment":
		var expected *bool
		if !decodeStrict(input, &expected) || expected == nil {
			return nil, "invalidArguments"
		}
		q.needsMIME = true
		return func(email *emailMeta) bool {
			s := &q.content
			return s.load(email) && (len(s.mime.attachments) > 0) == *expected
		}, ""
	case "header":
		var args []*string
		if !decodeStrict(input, &args) || len(args) < 1 || len(args) > 2 || args[0] == nil || *args[0] == "" ||
			strings.IndexFunc(*args[0], func(r rune) bool { return r <= ' ' || r >= 127 || r == ':' }) >= 0 {
			return nil, "invalidArguments"
		}
		name := nettextproto.CanonicalMIMEHeaderKey(*args[0])
		var terms []searchTerm
		if len(args) == 2 {
			if args[1] == nil {
				return nil, "invalidArguments"
			}
			terms = searchTerms(*args[1])
		}
		return func(email *emailMeta) bool {
			s := &q.content
			return s.load(email) && s.header.Has(name) && matchesSearch(terms, s.headerText(name))
		}, ""
	case "text", "body", "from", "to", "cc", "bcc", "subject":
		var value *string
		if !decodeStrict(input, &value) || value == nil {
			return nil, "invalidArguments"
		}
		terms := searchTerms(*value)
		q.needsMIME = q.needsMIME || property == "text" || property == "body"
		return func(email *emailMeta) bool {
			return q.content.load(email) && matchesSearch(terms, q.content.fields(property))
		}, ""
	default:
		return nil, "unsupportedFilter"
	}
}

func (s *emailSearch) load(email *emailMeta) bool {
	if s.loaded {
		return s.failure == ""
	}
	s.loaded = true
	s.headers = make(map[string][]string)
	if s.needsMIME {
		raw, failure := s.op.readRaw(email)
		s.failure = failure
		if failure == "" {
			s.mime, s.failure = parseMIME(raw, email.ID)
			if s.failure == "" {
				s.header = s.mime.rawHeader.Header
			}
		}
	} else {
		s.header, s.failure = s.op.readEmailHeaders(email)
	}
	return s.failure == ""
}

func (op *operation) readEmailHeaders(email *emailMeta) (textproto.Header, string) {
	section := &imap.FetchItemBodySection{Specifier: imap.PartSpecifierHeader, Peek: true,
		Partial: &imap.SectionPartial{Size: maxMIMEHeader + 1}}
	raw, failure := fetchEmailSection(op.client, email, section, maxMIMEHeader)
	if failure != "" {
		return textproto.Header{}, failure
	}
	op.rawBytes += int64(len(raw))
	if op.rawBytes > 12*maxRaw {
		return textproto.Header{}, "requestTooLarge"
	}
	header, err := textproto.ReadHeader(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return textproto.Header{}, "serverFail"
	}
	return header, ""
}

func (s *emailSearch) headerText(name string) []string {
	if values, cached := s.headers[name]; cached {
		return values
	}
	values := s.header.Values(name)
	for i, value := range values {
		values[i] = normalizeSearch(decodeSearchHeader(value))
	}
	s.headers[name] = values
	return values
}

func decodeSearchHeader(value string) string {
	decoder := &mime.WordDecoder{CharsetReader: charset.Reader}
	if decoded, err := decoder.DecodeHeader(value); err == nil {
		return decoded
	}
	return value
}

func (s *emailSearch) fields(property string) []string {
	switch property {
	case "body":
		return s.bodyText()
	case "text":
		var fields []string
		for _, name := range []string{"From", "To", "Cc", "Bcc", "Subject"} {
			fields = append(fields, s.headerText(name)...)
		}
		return append(fields, s.bodyText()...)
	default:
		return s.headerText(nettextproto.CanonicalMIMEHeaderKey(property))
	}
}

func (s *emailSearch) bodyText() []string {
	if s.body != nil {
		return s.body
	}
	s.body = []string{}
	for _, part := range s.mime.parts {
		mediaType := part.Data["type"].(string)
		if !strings.HasPrefix(mediaType, "text/") {
			continue
		}
		for _, value := range searchableBodyPart(part) {
			s.body = append(s.body, normalizeSearch(value))
		}
	}
	return s.body
}

func searchableBodyPart(part *bodyPart) []string {
	value := textValue(part.Value)
	if part.Data["type"] == "text/html" {
		text, attributes := visibleHTML(value)
		return append([]string{text}, attributes...)
	}
	return []string{value}
}

func visibleHTML(value string) (string, []string) {
	tokenizer := html.NewTokenizer(strings.NewReader(value))
	var output strings.Builder
	var attributes []string
	var hidden atom.Atom
	for {
		switch tokenizer.Next() {
		case html.ErrorToken:
			return output.String(), attributes
		case html.TextToken:
			if hidden == 0 {
				output.Write(tokenizer.Text())
			}
		case html.StartTagToken, html.SelfClosingTagToken, html.EndTagToken:
			token := tokenizer.Token()
			if hidden != 0 {
				if token.Type == html.EndTagToken && token.DataAtom == hidden {
					hidden = 0
				}
				continue
			}
			switch token.DataAtom {
			case atom.Head, atom.Style, atom.Script, atom.Template, atom.Title:
				if token.Type == html.StartTagToken {
					hidden = token.DataAtom
				}
				continue
			case atom.Br, atom.P, atom.Div, atom.Li, atom.Tr, atom.Td, atom.Th,
				atom.H1, atom.H2, atom.H3, atom.H4, atom.H5, atom.H6, atom.Blockquote, atom.Hr, atom.Pre:
				output.WriteByte(' ')
			}
			for _, attribute := range token.Attr {
				if attribute.Key == "alt" || attribute.Key == "title" {
					attributes = append(attributes, attribute.Val)
				}
			}
		}
	}
}

func normalizeSearch(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(value), " "))
}

type searchTerm struct {
	text   string
	phrase bool
}

func searchTerms(value string) []searchTerm {
	var terms []searchTerm
	for value = strings.TrimLeftFunc(value, unicode.IsSpace); value != ""; value = strings.TrimLeftFunc(value, unicode.IsSpace) {
		term, width := quotedSearchTerm(value)
		phrase := width != 0
		if width == 0 {
			width = strings.IndexFunc(value, unicode.IsSpace)
			if width < 0 {
				width = len(value)
			}
			term = value[:width]
		}
		if normalized := normalizeSearch(term); normalized != "" {
			terms = append(terms, searchTerm{normalized, phrase})
		}
		value = value[width:]
	}
	return terms
}

func quotedSearchTerm(value string) (string, int) {
	quote := value[0]
	if quote != '\'' && quote != '"' {
		return "", 0
	}
	var term strings.Builder
	for i := 1; i < len(value); i++ {
		if value[i] == quote {
			return term.String(), i + 1
		}
		if value[i] == '\\' && i+1 < len(value) && strings.ContainsRune(`'"\`, rune(value[i+1])) {
			i++
		}
		term.WriteByte(value[i])
	}
	return "", 0
}

func matchesSearch(terms []searchTerm, fields []string) bool {
	for _, term := range terms {
		if !slices.ContainsFunc(fields, term.matches) {
			return false
		}
	}
	return true
}

func (term searchTerm) matches(field string) bool {
	return term.find(field, 0) >= 0
}

func (term searchTerm) find(field string, offset int) int {
	if !term.phrase {
		if i := strings.Index(field[offset:], term.text); i >= 0 {
			return offset + i
		}
		return -1
	}
	first, _ := utf8.DecodeRuneInString(term.text)
	last, _ := utf8.DecodeLastRuneInString(term.text)
	word := func(r rune) bool { return unicode.IsLetter(r) || unicode.IsNumber(r) || unicode.IsMark(r) }
	for {
		i := strings.Index(field[offset:], term.text)
		if i < 0 {
			return -1
		}
		start := offset + i
		before, _ := utf8.DecodeLastRuneInString(field[:start])
		after, _ := utf8.DecodeRuneInString(field[start+len(term.text):])
		if !(word(first) && word(before)) && !(word(last) && word(after)) {
			return start
		}
		offset = start + 1
	}
}
