package gateway

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"mime/quotedprintable"
	"net/textproto"
	"strings"
	"time"
	"unicode"

	mailtextproto "github.com/emersion/go-message/textproto"
)

const maxDraftAttachmentBytes = 1 << 20

type draftInput struct {
	MailboxIDs    map[string]bool           `json:"mailboxIds"`
	Keywords      map[string]bool           `json:"keywords"`
	TextBody      []json.RawMessage         `json:"textBody"`
	HTMLBody      []json.RawMessage         `json:"htmlBody"`
	Attachments   []json.RawMessage         `json:"attachments"`
	BodyStructure *json.RawMessage          `json:"bodyStructure"`
	BodyValues    map[string]draftBodyValue `json:"bodyValues"`
}

type draftBodyValue struct {
	Value             *string `json:"value"`
	IsEncodingProblem bool    `json:"isEncodingProblem"`
	IsTruncated       bool    `json:"isTruncated"`
}

type draftPart struct {
	PartID      string            `json:"partId"`
	BlobID      string            `json:"blobId"`
	Type        string            `json:"type"`
	Charset     string            `json:"charset"`
	Name        string            `json:"name"`
	Disposition string            `json:"disposition"`
	CID         string            `json:"cid"`
	Language    []string          `json:"language"`
	Location    string            `json:"location"`
	Size        *int64            `json:"size"`
	SubParts    []json.RawMessage `json:"subParts"`
}

type encodedDraftPart struct {
	headers textproto.MIMEHeader
	extra   []draftHeader
	body    []byte
}

type draftMIMEBuilder struct {
	values    map[string]draftBodyValue
	used      map[string]bool
	missing   map[string]bool
	readBlob  func(string) ([]byte, string)
	count     int
	blobBytes int
}

func invalidDraft() object { return object{"type": "invalidProperties"} }

type draftMessage struct {
	raw        []byte
	mailboxIDs map[string]bool
	keywords   map[string]bool
}

func makeDraft(input json.RawMessage, now time.Time, allowsFrom func(string) bool, readBlob func(string) ([]byte, string)) (draftMessage, object) {
	var fields rawObject
	if !decodeStrict(input, &fields) || fields == nil {
		return draftMessage{}, invalidDraft()
	}
	headers, failure := draftHeaders(fields, now, allowsFrom)
	if failure != nil {
		return draftMessage{}, failure
	}
	var m draftInput
	if !decodeArgs(fields, &m) {
		return draftMessage{}, invalidDraft()
	}
	b := draftMIMEBuilder{values: m.BodyValues, used: make(map[string]bool), missing: make(map[string]bool), readBlob: readBlob}
	content, failure := b.body(m)
	if failure != nil {
		return draftMessage{}, failure
	}
	if len(b.missing) > 0 {
		return draftMessage{}, object{"type": "blobNotFound", "notFound": sortedKeys(b.missing)}
	}
	if len(b.used) != len(m.BodyValues) {
		return draftMessage{}, invalidDraft()
	}
	topNames := make(map[string]bool, len(headers))
	for _, header := range headers {
		topNames[header.name] = true
	}
	for _, header := range content.extra {
		if topNames[header.name] {
			return draftMessage{}, invalidProperty("header:" + header.name)
		}
	}
	var raw bytes.Buffer
	serializedHeaders := draftWireHeaders(content.headers, append(headers, content.extra...))
	_ = mailtextproto.WriteHeader(&raw, serializedHeaders)
	raw.Write(content.body)
	if !bytes.HasSuffix(raw.Bytes(), []byte("\r\n")) {
		raw.WriteString("\r\n")
	}
	if raw.Len() > maxRaw {
		return draftMessage{}, object{"type": "tooLarge", "maxSize": maxRaw}
	}
	return draftMessage{raw: raw.Bytes(), mailboxIDs: m.MailboxIDs, keywords: m.Keywords}, nil
}

func draftWireHeaders(generated textproto.MIMEHeader, extra []draftHeader) mailtextproto.Header {
	fields := mailtextproto.HeaderFromMap(generated)
	// AddRaw prepends fields. Walk backwards to keep the requested order.
	for i := len(extra) - 1; i >= 0; i-- {
		header := extra[i]
		fields.AddRaw([]byte(textproto.CanonicalMIMEHeaderKey(header.name) + ":" + header.value + "\r\n"))
	}
	return fields
}

func (b *draftMIMEBuilder) body(m draftInput) (encodedDraftPart, object) {
	if m.BodyStructure != nil {
		if m.TextBody != nil || m.HTMLBody != nil || m.Attachments != nil {
			return encodedDraftPart{}, invalidDraft()
		}
		return b.part(*m.BodyStructure, "", false, 0)
	}
	var bodies, attachments []encodedDraftPart
	for _, candidate := range []struct {
		parts []json.RawMessage
		kind  string
	}{{m.TextBody, "text/plain"}, {m.HTMLBody, "text/html"}} {
		if candidate.parts == nil {
			continue
		}
		if len(candidate.parts) != 1 {
			return encodedDraftPart{}, invalidDraft()
		}
		part, failure := b.part(candidate.parts[0], candidate.kind, false, 0)
		if failure != nil {
			return encodedDraftPart{}, failure
		}
		bodies = append(bodies, part)
	}
	for _, input := range m.Attachments {
		part, failure := b.part(input, "application/octet-stream", true, 0)
		if failure != nil {
			return encodedDraftPart{}, failure
		}
		attachments = append(attachments, part)
	}
	if len(bodies) == 2 {
		bodies = []encodedDraftPart{combineDraftParts("multipart/alternative", nil, nil, nil, bodies)}
		b.count++
	}
	if len(attachments) > 0 {
		bodies = []encodedDraftPart{combineDraftParts("multipart/mixed", nil, nil, nil, append(bodies, attachments...))}
		b.count++
	}
	if len(bodies) == 0 {
		return encodedDraftPart{headers: textproto.MIMEHeader{"Content-Type": {"text/plain; charset=utf-8"}}}, nil
	}
	if b.count > maxMIMEParts {
		return encodedDraftPart{}, invalidDraft()
	}
	return bodies[0], nil
}

func (b *draftMIMEBuilder) part(raw json.RawMessage, fallback string, attachment bool, depth int) (encodedDraftPart, object) {
	b.count++
	if b.count > maxMIMEParts || depth > maxMIMEDepth {
		return encodedDraftPart{}, invalidDraft()
	}
	p, extra, valid := decodeDraftPart(raw)
	if !valid {
		return encodedDraftPart{}, invalidDraft()
	}
	mediaType, params, valid := draftPartType(p, fallback, extra)
	if !valid || !strings.Contains(mediaType, "/") || strings.Contains(mediaType, "*") ||
		(strings.HasPrefix(mediaType, "message/") && mediaType != "message/rfc822" && mediaType != "message/global") ||
		(!attachment && fallback != "" && mediaType != fallback) {
		return encodedDraftPart{}, invalidDraft()
	}
	if !attachment && fallback != "" && p.Type == "" {
		if index, _ := partHeader(extra, "content-type"); index < 0 {
			return encodedDraftPart{}, invalidDraft()
		}
	}
	dispositionIndex, disposition := partHeader(extra, "content-disposition")
	if dispositionIndex >= 0 {
		if _, _, err := mime.ParseMediaType(strings.TrimSpace(unfoldDraftHeader(disposition))); err != nil {
			return encodedDraftPart{}, invalidDraft()
		}
	}
	headers, valid := draftPartHeaders(p, attachment && dispositionIndex < 0)
	if !valid {
		return encodedDraftPart{}, invalidDraft()
	}
	if strings.HasPrefix(mediaType, "multipart/") {
		switch mediaType {
		case "multipart/mixed", "multipart/alternative", "multipart/related", "multipart/digest", "multipart/parallel":
		default:
			return encodedDraftPart{}, invalidDraft()
		}
		if len(p.SubParts) == 0 || p.PartID != "" || p.BlobID != "" || p.Charset != "" || p.Size != nil {
			return encodedDraftPart{}, invalidDraft()
		}
		children := make([]encodedDraftPart, 0, len(p.SubParts))
		for _, child := range p.SubParts {
			part, failure := b.part(child, "", false, depth+1)
			if failure != nil {
				return encodedDraftPart{}, failure
			}
			children = append(children, part)
		}
		return combineDraftParts(mediaType, headers, extra, params, children), nil
	}
	if p.SubParts != nil || (p.PartID == "") == (p.BlobID == "") {
		return encodedDraftPart{}, invalidDraft()
	}
	if p.PartID != "" {
		value, found := b.values[p.PartID]
		if !strings.HasPrefix(mediaType, "text/") || !found || b.used[p.PartID] || value.Value == nil || value.IsTruncated || value.IsEncodingProblem ||
			len(*value.Value) > 65536 || strings.ContainsRune(*value.Value, 0) || p.Size != nil || p.Charset != "" {
			return encodedDraftPart{}, invalidDraft()
		}
		b.used[p.PartID] = true
		regenerate := params["charset"] == ""
		if !regenerate && !strings.EqualFold(params["charset"], "utf-8") {
			return encodedDraftPart{}, invalidDraft()
		}
		params["charset"] = "utf-8"
		extra = partTypeHeader(headers, extra, mediaType, params, regenerate)
		headers.Set("Content-Transfer-Encoding", "quoted-printable")
		return encodedDraftPart{headers: headers, extra: extra, body: draftQuotedPrintable(*value.Value)}, nil
	}
	if !jmapID.MatchString(strings.TrimPrefix(p.BlobID, "#")) || p.Size != nil && (*p.Size < 0 || *p.Size > maxJMAPInt) {
		return encodedDraftPart{}, invalidDraft()
	}
	if p.Charset != "" {
		if !strings.HasPrefix(mediaType, "text/") || !draftASCIIToken(p.Charset) {
			return encodedDraftPart{}, invalidDraft()
		}
		params = map[string]string{"charset": p.Charset}
	}
	body, failure := b.readBlob(p.BlobID)
	switch failure {
	case "notFound":
		b.missing[p.BlobID] = true
	case "":
	default:
		return encodedDraftPart{}, object{"type": failure}
	}
	b.blobBytes += len(body)
	if b.blobBytes > maxDraftAttachmentBytes {
		return encodedDraftPart{}, object{"type": "tooLarge", "maxSize": maxDraftAttachmentBytes}
	}
	extra = partTypeHeader(headers, extra, mediaType, params, false)
	if mediaType == "message/rfc822" || mediaType == "message/global" {
		encoding := "7bit"
		if failure != "notFound" {
			transport, valid := embeddedMessageTransport(body)
			if !valid || (mediaType == "message/global") != transport.utf8 {
				return encodedDraftPart{}, invalidProperty("blobId")
			}
			if transport.eightBit {
				encoding = "8bit"
			}
		}
		headers.Set("Content-Transfer-Encoding", encoding)
		return encodedDraftPart{headers: headers, extra: extra, body: body}, nil
	}
	headers.Set("Content-Transfer-Encoding", "base64")
	return encodedDraftPart{headers: headers, extra: extra, body: draftBase64(body)}, nil
}

func draftPartHeaders(p draftPart, attachment bool) (textproto.MIMEHeader, bool) {
	headers := make(textproto.MIMEHeader)
	disposition := strings.ToLower(p.Disposition)
	if disposition == "" && (attachment || p.Name != "") {
		disposition = "attachment"
	}
	if !safeDraftHeader(p.Name, 255) || disposition != "" && disposition != "attachment" && disposition != "inline" {
		return nil, false
	}
	if disposition != "" {
		var params map[string]string
		if p.Name != "" {
			params = map[string]string{"filename": p.Name}
		}
		headers.Set("Content-Disposition", mime.FormatMediaType(disposition, params))
	}
	if p.CID != "" {
		if !draftASCIIToken(p.CID) || strings.ContainsAny(p.CID, "<>") {
			return nil, false
		}
		headers.Set("Content-Id", "<"+p.CID+">")
	}
	if p.Location != "" {
		if !draftASCIIToken(p.Location) {
			return nil, false
		}
		headers.Set("Content-Location", p.Location)
	}
	if len(p.Language) > 0 {
		for _, tag := range p.Language {
			if !draftASCIIToken(tag) || strings.ContainsRune(tag, ',') {
				return nil, false
			}
		}
		language := strings.Join(p.Language, ", ")
		if len(language) > 512 {
			return nil, false
		}
		headers.Set("Content-Language", language)
	}
	return headers, true
}

func combineDraftParts(kind string, headers textproto.MIMEHeader, extra []draftHeader, parameters map[string]string, children []encodedDraftPart) encodedDraftPart {
	if headers == nil {
		headers = make(textproto.MIMEHeader)
	}
	if parameters == nil {
		parameters = make(map[string]string)
	}
	var body bytes.Buffer
	writer := mailtextproto.NewMultipartWriter(&body)
	parameters["boundary"] = writer.Boundary()
	if kind == "multipart/related" && parameters["type"] == "" {
		contentType := children[0].headers.Get("Content-Type")
		if _, value := partHeader(children[0].extra, "content-type"); value != "" {
			contentType = strings.TrimSpace(unfoldDraftHeader(value))
		}
		rootType, _, _ := strings.Cut(contentType, ";")
		parameters["type"] = strings.TrimSpace(rootType)
	}
	extra = partTypeHeader(headers, extra, kind, parameters, true)
	// The backing bytes.Buffer cannot return a write error.
	for _, part := range children {
		out, _ := writer.CreatePart(draftWireHeaders(part.headers, part.extra))
		_, _ = out.Write(part.body)
	}
	_ = writer.Close()
	return encodedDraftPart{headers: headers, extra: extra, body: body.Bytes()}
}

func safeDraftHeader(value string, limit int) bool {
	return len(value) <= limit && strings.IndexFunc(value, unicode.IsControl) < 0
}

func draftASCIIToken(value string) bool {
	return len(value) > 0 && len(value) <= 512 && strings.IndexFunc(value, func(r rune) bool { return r < 33 || r > 126 }) < 0
}

func draftQuotedPrintable(value string) []byte {
	var body bytes.Buffer
	writer := quotedprintable.NewWriter(&body)
	value = strings.NewReplacer("\r\n", "\n", "\r", "\n").Replace(value)
	_, _ = io.WriteString(writer, value)
	_ = writer.Close()
	return body.Bytes()
}

func draftBase64(data []byte) []byte {
	var body bytes.Buffer
	var line [76]byte
	for len(data) > 0 {
		n := min(len(data), 57)
		base64.StdEncoding.Encode(line[:], data[:n])
		body.Write(line[:base64.StdEncoding.EncodedLen(n)])
		body.WriteString("\r\n")
		data = data[n:]
	}
	return body.Bytes()
}
