package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
)

func TestDraftUploadsAndSubmissionOverTLS(t *testing.T) {
	config := testConfig(t)
	cert, ca := testTLS(t)
	config.DraftsMailbox = "Drafts"
	config.IMAP.Address, _ = serveTestIMAP(t, config.IMAP, cert, imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapUIDPlus: {}}, nil)
	config.IMAP.CAFile, config.SMTP.CAFile = ca, ca
	address, relay := serveTestSMTP(t, config.SMTP, cert, "")
	config.SMTP.Address = address
	g, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	data := bytes.Repeat([]byte{0, 0xFF, '\r', '\n', 0x80, 'x'}, 40)
	upload := uploadRequest(g, config.Token, "application/octet-stream", bytes.NewReader(data))
	var blob object
	if upload.Code != http.StatusCreated || json.Unmarshal(upload.Body.Bytes(), &blob) != nil {
		t.Fatalf("upload: %s", upload.Body)
	}
	draft := draftFixture(mailboxID(config.AccountID, "Drafts"), config.IdentityEmail)
	draft["textBody"] = []object{{"partId": "plain", "header:Content-Type": " text/plain; format=flowed"}}
	draft["htmlBody"] = []object{{"partId": "html", "type": "text/html"}}
	draft["bodyValues"] = object{"plain": object{"value": "Hei\n.rauha"}, "html": object{"value": "<p>Hei</p>"}}
	draft["attachments"] = []object{{"blobId": blob["blobId"], "header:Content-Type": "application/octet-stream", "size": 1,
		"header:Content-Disposition": " attachment; filename*=utf-8''tiedosto-%C3%A4.bin",
		"header:Content-Id":          " <test@example.test>", "header:Content-Language": " fi, en",
		"header:Content-Location": " files/test.bin", "header:X-Part:all": []string{"one", " two\r\n three"}}}

	flow := gatewayCalls(t, g, config.Token,
		[3]any{"Email/set", object{"accountId": config.AccountID, "create": object{"draft": draft}}, "draft"},
		[3]any{"Email/get", object{"accountId": config.AccountID, "ids": []string{"#draft"}, "fetchAllBodyValues": true,
			"bodyProperties": []string{"blobId", "name", "size", "cid", "language", "location", "header:X-Part:all", "header:Content-Type"}}, "read"},
		[3]any{"EmailSubmission/set", object{"accountId": config.AccountID, "create": object{"send": object{"emailId": "#draft", "identityId": identityID}}}, "send"})
	if flow[0].Name != "Email/set" || flow[0].Args["created"] == nil || flow[1].Name != "Email/get" ||
		flow[2].Name != "EmailSubmission/set" || flow[2].Args["created"] == nil {
		t.Fatalf("draft creation and submission: %v", flow)
	}
	message := flow[1].Args["list"].([]any)[0].(map[string]any)
	attachment := message["attachments"].([]any)[0].(map[string]any)
	if message["hasAttachment"] != true || len(message["textBody"].([]any)) != 1 || len(message["htmlBody"].([]any)) != 1 ||
		attachment["name"] != "tiedosto-ä.bin" || attachment["size"] != float64(len(data)) || attachment["cid"] != "test@example.test" ||
		attachment["location"] != "files/test.bin" || !reflect.DeepEqual(attachment["language"], []any{"fi", "en"}) ||
		attachment["header:Content-Type"] != "application/octet-stream" || !reflect.DeepEqual(attachment["header:X-Part:all"], []any{"one", " two\r\n three"}) {
		t.Fatalf("IMAP MIME structure: %v", message)
	}
	got := gatewayRequest(g, http.MethodGet, "/download/"+config.AccountID+"/"+attachment["blobId"].(string)+"/part.bin", config.Token, nil)
	if got.Code != http.StatusOK || !bytes.Equal(got.Body.Bytes(), data) {
		t.Fatalf("downloaded IMAP attachment changed bytes: %d", got.Code)
	}
	select {
	case raw := <-relay.received:
		// The SMTP fixture records the data before removing dot stuffing.
		raw = strings.ReplaceAll(raw, "\r\n..", "\r\n.")
		m, failure := parseMIME([]byte(raw), message["id"].(string))
		if failure != "" || len(m.attachments) != 1 || !bytes.Equal(m.attachments[0].Octets, data) ||
			len(m.html) != 1 || string(m.html[0].Value) != "<p>Hei</p>" || len(m.plain) != 1 ||
			!strings.Contains(textValue(m.plain[0].Value), "Hei\n.rauha") ||
			!strings.Contains(raw, "X-Part:one\r\nX-Part: two\r\n three\r\n") {
			t.Fatalf("SMTP MIME contents don't match the draft: %v", failure)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SMTP test message was not received")
	}
	if err := <-relay.done; err != nil {
		t.Fatal(err)
	}
	draft["attachments"] = []object{{"blobId": "missing2"}, {"blobId": "missing1"}, {"blobId": "missing2"}}
	missing := gatewayCalls(t, g, config.Token, [3]any{"Email/set", object{"accountId": config.AccountID, "create": object{"draft": draft}}, "missing"})[0]
	if missing.Name != "Email/set" || missing.Args["created"] != nil || missing.Args["oldState"] != missing.Args["newState"] ||
		!reflect.DeepEqual(missing.Args["notCreated"].(map[string]any)["draft"], map[string]any{"type": "blobNotFound", "notFound": []any{"missing1", "missing2"}}) {
		t.Fatalf("missing blobs must reject atomically and list all IDs: %v", missing)
	}
}

func draftFixture(drafts, sender string) object {
	return object{"mailboxIds": object{drafts: true}, "from": []object{{"email": sender}},
		"to": []object{{"email": "recipient@example.test"}}, "subject": "MIME draft fixture"}
}

func TestDraftBodyStructureAndValidation(t *testing.T) {
	const sender = "sender@example.test"
	input := func(parts object) json.RawMessage {
		draft := draftFixture("drafts", sender)
		for key, value := range parts {
			draft[key] = value
		}
		data, err := json.Marshal(draft)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	build := func(parts object) ([]byte, object) {
		draft, failure := makeDraft(input(parts), time.Now(), func(value string) bool { return value == sender }, func(id string) ([]byte, string) {
			switch id {
			case "offline":
				return nil, "serverUnavailable"
			case "big":
				return bytes.Repeat([]byte{1}, maxDraftAttachmentBytes+1), ""
			default:
				return []byte("caf\xe9"), ""
			}
		})
		return draft.raw, failure
	}
	inline := object{"partId": "plain", "type": "text/plain"}
	values := object{"plain": object{"value": "Body"}}
	structure := object{"type": "multipart/related", "subParts": []object{inline,
		{"blobId": "file", "type": "text/plain", "charset": "iso-8859-1", "name": "text-café.txt", "disposition": "inline",
			"cid": "file@example.test", "language": []string{"fi"}, "location": "files/cafe.txt"}}}
	raw, failure := build(object{"bodyStructure": structure, "bodyValues": values})
	if failure != nil {
		t.Fatalf("create explicit MIME structure: %v", failure)
	}
	parsed, code := parseMIME(raw, "e-test")
	if code != "" || parsed.structure.Data["type"] != "multipart/related" || len(parsed.attachments) != 1 ||
		string(parsed.attachments[0].Value) != "café" || parsed.attachments[0].Data["cid"] != "file@example.test" ||
		parsed.attachments[0].Data["location"] != "files/cafe.txt" || !reflect.DeepEqual(parsed.attachments[0].Data["language"], []string{"fi"}) || !bytes.Equal(parsed.attachments[0].Octets, []byte("caf\xe9")) {
		t.Fatalf("explicit MIME structure lost its blob encoding: %q", code)
	}
	if _, result := prepareSubmission([]byte(strings.Replace(string(raw), "boundary=", "ignored=", 1)), sender, nil); result["type"] != "invalidEmail" {
		t.Fatalf("malformed multipart body accepted for SMTP: %v", result)
	}
	duplicateID := []byte("Message-ID: <00000000000000000000000000000000@jmap.invalid>\r\n" + string(raw))
	if _, result := prepareSubmission(duplicateID, sender, nil); result["type"] != "invalidEmail" {
		t.Fatalf("duplicate message ID accepted for SMTP: %v", result)
	}
	for _, tc := range []struct {
		props object
		code  string
	}{
		{object{"textBody": []object{}}, "invalidProperties"}, {object{"bodyStructure": structure, "textBody": []object{inline}}, "invalidProperties"},
		{object{"textBody": []object{{"type": "text/html", "partId": "plain"}}, "bodyValues": values}, "invalidProperties"},
		{object{"textBody": []object{inline}, "bodyValues": object{"plain": object{"value": "Body"}, "unused": object{"value": "other"}}}, "invalidProperties"},
		{object{"textBody": []object{inline}, "bodyValues": object{"plain": object{"value": "Body", "isTruncated": true}}}, "invalidProperties"},
		{object{"bodyStructure": object{"type": "multipart/signed", "subParts": []object{inline}}}, "invalidProperties"},
		{object{"bodyStructure": object{"type": "multipart/mixed"}}, "invalidProperties"},
		{object{"bodyStructure": object{"type": "multipart/mixed", "subParts": []object{{"type": "not-a-type"}}}}, "invalidProperties"},
		{object{"attachments": []object{{"type": "image/png", "blobId": "file", "partId": "plain"}}}, "invalidProperties"},
		{object{"attachments": []object{{"blobId": "file", "name": "bad\r\nname"}}}, "invalidProperties"},
		{object{"attachments": []object{{"blobId": "file", "cid": "<invalid>"}}}, "invalidProperties"},
		{object{"attachments": []object{{"blobId": "file", "location": "bad location"}}}, "invalidProperties"},
		{object{"attachments": []object{{"blobId": "file", "language": []string{"en,fi"}}}}, "invalidProperties"},
		{object{"attachments": []object{{"blobId": "file", "language": []string{strings.Repeat("x", 400), strings.Repeat("y", 400)}}}}, "invalidProperties"},
		{object{"attachments": []object{{"blobId": "invalid id"}}}, "invalidProperties"},
		{object{"attachments": []object{{"blobId": "file", "type": "application/octet-stream", "charset": "utf-8"}}}, "invalidProperties"},
		{object{"attachments": []object{{"blobId": "offline"}}}, "serverUnavailable"},
		{object{"attachments": []object{{"blobId": "big"}}}, "tooLarge"},
	} {
		if body, failure := build(tc.props); body != nil || failure["type"] != tc.code {
			t.Fatalf("invalid draft %v: %v, wanted %s", tc.props, failure, tc.code)
		}
	}
	var deep object = inline
	for range maxMIMEDepth + 1 {
		deep = object{"type": "multipart/mixed", "subParts": []object{deep}}
	}
	if _, failure := build(object{"bodyStructure": deep, "bodyValues": values}); failure["type"] != "invalidProperties" {
		t.Fatalf("excessive MIME nesting: %v", failure)
	}
	attachments := make([]object, maxMIMEParts)
	for i := range attachments {
		attachments[i] = object{"blobId": "file"}
	}
	if _, failure := build(object{"attachments": attachments[:maxMIMEParts-1]}); failure != nil {
		t.Fatalf("attachments at the MIME part limit: %v", failure)
	}
	if wire, failure := build(object{"attachments": attachments}); wire != nil || failure["type"] != "invalidProperties" {
		t.Fatalf("generated multipart root did not count toward the MIME part limit: %v", failure)
	}
	var parts []object
	many := make(object)
	for i := range 16 {
		id := fmt.Sprint(i)
		parts = append(parts, object{"type": "text/plain", "partId": id})
		many[id] = object{"value": strings.Repeat("ä", 30000)}
	}
	if _, failure := build(object{"bodyStructure": object{"type": "multipart/mixed", "subParts": parts}, "bodyValues": many}); failure["type"] != "tooLarge" ||
		failure["maxSize"] != maxRaw {
		t.Fatalf("encoded size limit: %v", failure)
	}
}
