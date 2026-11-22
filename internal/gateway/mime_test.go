package gateway

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestDraftValidation(t *testing.T) {
	for _, test := range []struct {
		name, part, value, recipient, keywords string
		want                                   string
	}{
		{"valid", `{"partId":"1","type":"text/plain"}`, `"hello"`, `{"email":"to@example.test"}`, `{"$seen":true}`, ""},
		{"bad charset", `{"partId":"1","type":"text/plain","charset":"unknown"}`, `"hello"`, `{"email":"to@example.test"}`, `{}`, "invalidProperties"},
		{"missing value", `{"partId":"1","type":"text/plain"}`, `null`, `{"email":"to@example.test"}`, `{}`, "invalidProperties"},
		{"invalid recipient", `{"partId":"1","type":"text/plain"}`, `"hello"`, `{"email":"to@example.test\r\n"}`, `{}`, "invalidProperties"},
		{"invalid name", `{"partId":"1","type":"text/plain"}`, `"hello"`, `{"email":"to@example.test","name":"name\nwrong"}`, `{}`, "invalidProperties"},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := fmt.Sprintf(`{"mailboxIds":{"drafts":true},"from":[{"email":"from@example.test"}],
				"to":[%s],"keywords":%s,"textBody":[%s],"bodyValues":{"1":{"value":%s}}}`,
				test.recipient, test.keywords, test.part, test.value)
			draft, result := makeDraft(json.RawMessage(input), time.Now(), func(value string) bool { return value == "from@example.test" }, nil)
			body, seen := draft.raw, draft.keywords["$seen"]
			code, _ := result["type"].(string)
			if code != test.want || (result == nil && (len(body) == 0 || !seen)) {
				t.Fatalf("unexpected draft result %v, bytes %d, seen %t", result, len(body), seen)
			}
		})
	}
}

func TestSubmissionEnvelopeRestrictions(t *testing.T) {
	const base = "From: from@example.test\r\nTo: to@example.test\r\nMessage-ID: <0123456789abcdef0123456789abcdef@jmap.invalid>\r\nContent-Type: text/plain\r\n"
	for _, test := range []struct{ input, want string }{
		{"invalid header\r\n\r\n", "invalidEmail"},
		{base + "Resent-From: someone@example.test\r\n\r\n", "invalidEmail"},
		{strings.Replace(base, "from@example.test", "other@example.test", 1) + "\r\n", "forbiddenFrom"},
		{base + "Cc: not-an-address\r\n\r\n", "invalidEmail"},
		{strings.Replace(base, "text/plain", "text/html", 1) + "\r\n", "invalidEmail"},
	} {
		if _, got := prepareSubmission([]byte(test.input), "from@example.test", nil); got["type"] != test.want {
			t.Errorf("got %v, want %s", got, test.want)
		}
	}
}

func TestMIMEStructureAndAttachments(t *testing.T) {
	raw := []byte(strings.Join([]string{
		"Subject: =?x-unsupported?Q?Unable_to_decode?=",
		"Message-ID: <from-example@example.test>",
		"References: <earlier@example.test> <second@example.test>",
		"Content-Type: multipart/mixed; boundary=parts",
		"",
		"--parts",
		"Content-Type: text/plain; charset=utf-8",
		"Content-Language: en, fi",
		"",
		"plain",
		"--parts",
		"Content-Type: text/html; charset=utf-8",
		"",
		"<p>HTML</p>",
		"--parts",
		"Content-Type: application/pdf",
		"Content-Disposition: attachment; filename=example.pdf",
		"Content-Transfer-Encoding: base64",
		"",
		"UEZERGF0YQ==",
		"--parts",
		"Content-Type: invalid value",
		"",
		"other",
		"--parts--",
		"",
	}, "\r\n"))
	meta := emailMeta{ID: emailID("drafts", 1, 1)}
	parsed, failure := parseMIME(raw, meta.ID)
	if failure != "" {
		t.Fatal(failure)
	}
	if len(parsed.plain) != 1 || len(parsed.html) != 1 || len(parsed.attachments) != 2 {
		t.Fatalf("unexpected MIME parts: text=%d, HTML=%d, attachments=%d", len(parsed.plain), len(parsed.html), len(parsed.attachments))
	}
	if got := parsed.attachments[0]; string(got.Value) != "PFDData" || got.Data["name"] != "example.pdf" {
		t.Fatalf("wrong attachment: %v", got.Data)
	}
	fields := getArgs{
		Properties:     []string{"headers", "bodyValues", "bodyStructure", "subject", "references"},
		BodyProperties: []string{"partId", "type"}, FetchAllBodyValues: true,
	}
	record := parsed.emailRecord(&meta, fields)
	first := record["bodyStructure"].(object)["subParts"].([]object)[0]
	values := record["bodyValues"].(object)
	if first["type"] != "text/plain" || len(values) != 2 || len(record["headers"].([]object)) != 4 ||
		record["subject"] != "\uFFFD" || len(record["references"].([]string)) != 2 {
		t.Fatalf("unexpected MIME projection: %v", record)
	}
	fields.FetchAllBodyValues = false
	fields.FetchHTMLBodyValues = true
	values = parsed.emailRecord(&meta, fields)["bodyValues"].(object)
	if len(values) != 1 || values["1_2"].(object)["value"] != "<p>HTML</p>" {
		t.Fatalf("unexpected HTML body: %v", values)
	}
}

func TestMIMELimits(t *testing.T) {
	var nested strings.Builder
	for depth := range 14 {
		fmt.Fprintf(&nested, "Content-Type: multipart/mixed; boundary=x%d\r\n\r\n--x%d\r\n", depth, depth)
	}
	nested.WriteString("Content-Type: text/plain\r\n\r\nhello\r\n")
	for depth := 13; depth >= 0; depth-- {
		fmt.Fprintf(&nested, "--x%d--\r\n", depth)
	}
	for _, raw := range []string{
		"bad header\r\n\r\n",
		"Subject: " + strings.Repeat("x", 129<<10) + "\r\n\r\n",
		"Content-Type: multipart/mixed; boundary=parts\r\n\r\n--parts\r\ninvalid header\r\n\r\n",
		"Content-Type: text/plain\r\n\r\n" + strings.Repeat("x", 4*maxRaw+1),
		nested.String(),
	} {
		if _, failure := parseMIME([]byte(raw), emailID("drafts", 1, 1)); failure != "serverFail" {
			t.Fatalf("unacceptable MIME of size %d returned %q", len(raw), failure)
		}
	}
}

func TestMimeEncodedOctetsAndRawHeaders(t *testing.T) {
	id := emailID("fixture", 1, 1)
	raw := []byte("sUBJect: Original\r\nX-Order: one\r\nX-Fold: a\r\n\t b\r\nX-Order: two\r\n" +
		"Content-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n=E9")
	message, failure := parseMIME(raw, id)
	if failure != "" || len(message.plain) != 1 {
		t.Fatalf("MIME parse failed: %q", failure)
	}
	part := message.plain[0]
	if string(part.Octets) != "\xe9" || string(part.Value) != "é" || part.Data["size"] != 1 ||
		part.Data["charset"] != "iso-8859-1" || part.Problem {
		t.Fatalf("transfer bytes %x, display bytes %x, attributes %v", part.Octets, part.Value, part.Data)
	}
	a := getArgs{Properties: []string{"headers", "textBody", "bodyValues"}, BodyProperties: []string{"headers"}, FetchTextBodyValues: true}
	record := message.messageRecord(a)
	headers := record["headers"].([]object)
	if headers[0]["name"] != "sUBJect" || headers[0]["value"] != " Original" ||
		headers[1]["value"] != " one" || headers[2]["value"] != " a\r\n\t b" || headers[3]["value"] != " two" {
		t.Fatalf("incorrect header order, case or original folding: %v", headers)
	}
	p := record["textBody"].([]object)[0]
	if len(p) != 1 || len(p["headers"].([]object)) != len(headers) {
		t.Fatal("part header projection differs from the root header")
	}

	digest := "Subject: Digest\r\nContent-Type: multipart/digest; boundary=fixture\r\n\r\n" +
		"--fixture\r\n\r\nSubject: Attached\r\n\r\nhello\r\n--fixture--\r\n"
	parsed, failure := parseMIME([]byte(digest), id)
	if failure != "" || len(parsed.attachments) != 1 || parsed.attachments[0].Data["type"] != "message/rfc822" ||
		!strings.HasPrefix(string(parsed.attachments[0].Octets), "Subject: Attached") {
		t.Fatalf("default MIME type in multipart/digest: %q", failure)
	}
}

func TestCharsetDecodeFailuresAndLimit(t *testing.T) {
	id := emailID("fixture", 1, 1)
	failed := "Subject: Unknown charset\r\nContent-Type: text/plain; charset=not-a-valid-encoding\r\n\r\nvalue"
	m, failure := parseMIME([]byte(failed), id)
	if failure != "" || !m.plain[0].Problem || string(m.plain[0].Octets) != "value" {
		t.Fatalf("unknown charset did not preserve source bytes: %q", failure)
	}
	massive := "Subject: Too large\r\nContent-Type: text/plain; charset=iso-8859-1\r\n\r\n" +
		strings.Repeat("\xe9", 3*maxRaw/2)
	if _, failure := parseMIME([]byte(massive), id); failure != "serverFail" {
		t.Fatalf("character-set expansion exceeded the limit: %q", failure)
	}
}
