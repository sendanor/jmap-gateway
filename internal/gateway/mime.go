package gateway

import (
	"bufio"
	"bytes"
	"io"
	"net/mail"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/emersion/go-message"
	"github.com/emersion/go-message/charset"
	"github.com/emersion/go-message/textproto"
)

type object = map[string]any

type address struct {
	Name  *string `json:"name"`
	Email string  `json:"email"`
}

func validMessageID(value string) bool {
	if len(value) > 254 || strings.IndexFunc(value, func(r rune) bool {
		return r <= ' ' || r >= 127 || strings.ContainsRune("<>()[],:;\\\"", r)
	}) >= 0 {
		return false
	}
	a, err := mail.ParseAddress(value)
	return err == nil && a.Address == value && a.Name == ""
}

func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func addresses(header mail.Header, key string) []address {
	items, err := header.AddressList(key)
	if err != nil {
		return nil
	}
	out := make([]address, 0, len(items))
	for _, item := range items {
		a := address{Email: item.Address}
		if item.Name != "" {
			a.Name = &item.Name
		}
		out = append(out, a)
	}
	return out
}

func addressHeader(a address) string {
	name := ""
	if a.Name != nil {
		name = *a.Name
	}
	return (&mail.Address{Name: name, Address: a.Email}).String()
}

type bodyPart struct {
	Data    object
	Value   []byte
	Octets  []byte
	Problem bool
}

type mimeMessage struct {
	header                        mail.Header
	rawHeader                     message.Header
	structure                     *bodyPart
	plain, html, attachments      []*bodyPart
	parts                         map[string]*bodyPart
	count                         int
	decodedBytes                  int
	headerUTF8, invalidHeaderUTF8 bool
}

const (
	maxMIMEHeader = 128 << 10
	maxMIMEParts  = 128
	maxMIMEDepth  = 12
)

func parseMIME(raw []byte, email string) (*mimeMessage, string) {
	parsed, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil, "serverFail"
	}
	limited := &io.LimitedReader{R: bytes.NewReader(raw), N: maxMIMEHeader}
	reader := bufio.NewReader(limited)
	rawHeader, err := textproto.ReadHeader(reader)
	if err != nil {
		return nil, "serverFail"
	}
	limited.N = int64(len(raw))
	header := message.Header{Header: rawHeader}
	result := &mimeMessage{header: parsed.Header, rawHeader: header, parts: make(map[string]*bodyPart)}
	part, ok := result.walk(header, reader, "1", email, "text/plain", 0, false)
	if !ok {
		return nil, "serverFail"
	}
	result.structure = part
	return result, ""
}

func partBlobID(container, part string) string {
	switch container[0] {
	case 'u':
		return "q-" + container[2:] + "-" + part
	case 'p', 'q', 'r':
		return container + "-" + part
	default:
		return "r-" + container[2:] + "-" + part
	}
}

func (m *mimeMessage) walk(header message.Header, body io.Reader, id, email, fallbackType string, depth int, attached bool) (*bodyPart, bool) {
	m.count++
	if depth > maxMIMEDepth || m.count > maxMIMEParts {
		return nil, false
	}
	mediaType, params, typeErr := header.ContentType()
	switch {
	case typeErr != nil:
		mediaType = "application/octet-stream"
	case header.Get("Content-Type") == "":
		mediaType = fallbackType
	}
	textPart := strings.HasPrefix(mediaType, "text/")
	charsetName := params["charset"]
	if textPart && charsetName == "" {
		charsetName = "us-ascii"
	}
	disposition, dispParams, _ := header.ContentDisposition()
	name := dispParams["filename"]
	if name == "" {
		name = params["name"]
	}
	attached = attached || disposition == "attachment" || name != ""
	var languages []string
	for _, language := range strings.Split(header.Get("Content-Language"), ",") {
		if tag := strings.TrimSpace(language); tag != "" {
			languages = append(languages, tag)
		}
	}
	headers, utf8Header, invalidUTF8 := scanPartHeaders(header.Fields())
	m.headerUTF8 = m.headerUTF8 || utf8Header
	m.invalidHeaderUTF8 = m.invalidHeaderUTF8 || invalidUTF8
	part := &bodyPart{Data: object{
		"partId": id, "blobId": partBlobID(email, id), "type": mediaType,
		"charset": nullable(charsetName), "name": nullable(name),
		"headers":     headers,
		"disposition": nullable(disposition), "cid": nullable(strings.Trim(header.Get("Content-Id"), "<>")),
		"language": languages, "location": nullable(header.Get("Content-Location")),
	}}
	if strings.HasPrefix(mediaType, "multipart/") {
		reader := textproto.NewMultipartReader(body, params["boundary"])
		childType := "text/plain"
		if mediaType == "multipart/digest" {
			childType = "message/rfc822"
		}
		part.Data["partId"], part.Data["blobId"], part.Data["size"] = nil, nil, 0
		children := make([]object, 0)
		for index := 1; ; index++ {
			child, err := reader.NextPart()
			if err == io.EOF {
				break
			}
			if child == nil {
				return nil, false
			}
			p, ok := m.walk(message.Header{Header: child.Header}, child, id+"_"+strconv.Itoa(index), email, childType, depth+1, attached)
			if !ok {
				return nil, false
			}
			children = append(children, p.Data)
		}
		part.Data["subParts"] = children
		return part, true
	}
	// Decode transfer encoding independently. The blob contains the decoded
	// octets before character-set conversion used for display.
	var transport message.Header
	transport.Set("Content-Transfer-Encoding", header.Get("Content-Transfer-Encoding"))
	entity, encodingErr := message.New(transport, body)
	octets, truncated, err := take(entity.Body, int64(4*maxRaw-m.decodedBytes))
	if truncated {
		return nil, false
	}
	m.decodedBytes += len(octets)
	part.Problem = encodingErr != nil || err != nil
	part.Value, part.Octets = octets, octets
	part.Data["size"] = len(octets)
	if textPart && params["charset"] != "" && !strings.EqualFold(charsetName, "utf-8") && !strings.EqualFold(charsetName, "us-ascii") {
		decoded, charsetErr := charset.Reader(charsetName, bytes.NewReader(octets))
		if charsetErr != nil {
			part.Problem = true
		} else {
			value, truncated, err := take(decoded, int64(4*maxRaw-m.decodedBytes))
			if truncated {
				return nil, false
			}
			m.decodedBytes += len(value)
			part.Value = value
			part.Problem = part.Problem || err != nil
		}
	}
	m.parts[id] = part
	switch {
	case !attached && mediaType == "text/plain":
		m.plain = append(m.plain, part)
	case !attached && mediaType == "text/html":
		m.html = append(m.html, part)
	default:
		m.attachments = append(m.attachments, part)
	}
	return part, true
}

func textValue(value []byte) string {
	return strings.ReplaceAll(strings.ToValidUTF8(string(value), "\uFFFD"), "\r\n", "\n")
}

func truncateUTF8(text string, limit int) (string, bool) {
	if limit <= 0 || len(text) <= limit {
		return text, false
	}
	for !utf8.RuneStart(text[limit]) {
		limit--
	}
	return text[:limit], true
}

func (m *mimeMessage) emailRecord(email *emailMeta, a getArgs) object {
	record := m.messageRecord(a)
	for key, value := range email.fields() {
		record[key] = value
	}
	return record
}

var defaultBodyProperties = []string{
	"partId", "blobId", "size", "name", "type", "charset", "disposition", "cid", "language", "location",
}

func (m *mimeMessage) messageRecord(a getArgs) object {
	if a.BodyProperties == nil {
		a.BodyProperties = defaultBodyProperties
	}
	var preview string
	if len(m.plain) > 0 {
		preview, _ = truncateUTF8(strings.Join(strings.Fields(textValue(m.plain[0].Value)), " "), 256)
	}
	partList := func(parts []*bodyPart) []object {
		out := make([]object, 0, len(parts))
		for _, part := range parts {
			out = append(out, projectBodyPart(part.Data, a))
		}
		return out
	}
	values := make(object)
	addValue := func(part *bodyPart) {
		val, truncated := truncateUTF8(textValue(part.Value), a.MaxBodyValueBytes)
		values[part.Data["partId"].(string)] = object{
			"value": val, "isTruncated": truncated, "isEncodingProblem": part.Problem || !utf8.Valid(part.Value),
		}
	}
	if contains(a.Properties, "bodyValues") {
		if a.FetchAllBodyValues {
			for _, part := range m.parts {
				if strings.HasPrefix(part.Data["type"].(string), "text/") {
					addValue(part)
				}
			}
		} else {
			if a.FetchTextBodyValues {
				for _, part := range m.plain {
					addValue(part)
				}
			}
			if a.FetchHTMLBodyValues {
				for _, part := range m.html {
					addValue(part)
				}
			}
		}
	}
	headers := rawHeaders(m.rawHeader.Fields())
	record := object{
		"preview": preview, "hasAttachment": len(m.attachments) > 0,
		"textBody": partList(m.plain), "htmlBody": partList(m.html), "attachments": partList(m.attachments),
		"bodyStructure": partObject(m.structure.Data, a), "bodyValues": values, "headers": headers,
	}
	renderHeaderProjections(record, headers, namedEmailHeaders)
	renderHeaderProjections(record, headers, a.headerFields)
	return record
}

func rawHeaders(fields textproto.HeaderFields) []object {
	headers, _, _ := scanPartHeaders(fields)
	return headers
}

func scanPartHeaders(fields textproto.HeaderFields) ([]object, bool, bool) {
	headers := make([]object, 0)
	var international, invalid bool
	for fields.Next() {
		raw, err := fields.Raw()
		international = international || containsEightBit(raw)
		invalid = invalid || err != nil || !utf8.Valid(raw) || bytes.IndexByte(raw, 0) >= 0
		line := strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
		name, value, _ := strings.Cut(line, ":")
		value = strings.ToValidUTF8(strings.ReplaceAll(value, "\x00", ""), "\uFFFD")
		headers = append(headers, object{"name": name, "value": value})
	}
	return headers, international, invalid
}

func projectBodyPart(data object, args getArgs) object {
	out := project(data, args.BodyProperties)
	renderHeaderProjections(out, data["headers"].([]object), args.bodyHeaderFields)
	return out
}

func partObject(data object, args getArgs) object {
	out := projectBodyPart(data, args)
	if parts, ok := data["subParts"].([]object); ok {
		children := make([]object, 0, len(parts))
		for _, child := range parts {
			children = append(children, partObject(child, args))
		}
		out["subParts"] = children
	}
	return out
}
