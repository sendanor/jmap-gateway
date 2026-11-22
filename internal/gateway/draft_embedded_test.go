package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
)

func TestDraftMessageAttachmentThroughIMAPAndSMTP(t *testing.T) {
	cfg := testConfig(t)
	cfg.DraftsMailbox = "Drafts"
	cert, ca := testTLS(t)
	cfg.IMAP.Address, _ = serveTestIMAP(t, cfg.IMAP, cert, imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapUIDPlus: {}}, nil)
	cfg.IMAP.CAFile, cfg.SMTP.CAFile = ca, ca
	var relay *smtpFixture
	cfg.SMTP.Address, relay = serveTestSMTP(t, cfg.SMTP, cert, "")
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	const embedded = "From: original@example.test\r\nDate: Sun, 22 Nov 2026 20:00:00 +0000\r\n" +
		"Subject: Embedded fixture\r\nBcc: historical@example.test\r\nContent-Type: text/plain\r\n\r\n.First\r\nLast\r\n"
	upload := uploadRequest(g, cfg.Token, "message/rfc822", strings.NewReader(embedded))
	var blob object
	if upload.Code != http.StatusCreated || json.Unmarshal(upload.Body.Bytes(), &blob) != nil {
		t.Fatalf("upload failed: %d %s", upload.Code, upload.Body)
	}
	drafts := mailboxID(cfg.AccountID, "Drafts")
	draft := draftFixture(drafts, cfg.IdentityEmail)
	draft["textBody"] = []object{{"partId": "text", "type": "text/plain"}}
	draft["bodyValues"] = object{"text": object{"value": "Forwarding the original."}}
	draft["attachments"] = []object{{"type": "message/rfc822", "name": "forwarded.eml", "blobId": blob["blobId"]}}
	flow := gatewayCalls(t, g, cfg.Token,
		[3]any{"Email/import", object{"accountId": cfg.AccountID, "emails": object{
			"stored": object{"blobId": blob["blobId"], "mailboxIds": object{mailboxID(cfg.AccountID, "Plain"): true}},
		}}, "store-source"})
	source := flow[0].Args["created"].(map[string]any)["stored"].(map[string]any)
	draft["attachments"].([]object)[0]["blobId"] = source["blobId"]
	flow = gatewayCalls(t, g, cfg.Token,
		[3]any{"Email/set", object{"accountId": cfg.AccountID, "create": object{"draft": draft}}, "compose"},
		[3]any{"Email/get", object{"accountId": cfg.AccountID, "ids": []string{"#draft"}, "properties": []string{"attachments", "bodyStructure"},
			"bodyProperties": []string{"partId", "type", "size", "blobId", "name", "header:Content-Transfer-Encoding:asText"}}, "get"},
		[3]any{"EmailSubmission/set", object{"accountId": cfg.AccountID, "create": object{"send": object{"emailId": "#draft", "identityId": identityID}}}, "send"})
	if flow[0].Args["created"] == nil || flow[2].Args["created"] == nil {
		t.Fatalf("forwarding flow failed: %v", flow)
	}
	record := flow[1].Args["list"].([]any)[0].(map[string]any)
	part := record["attachments"].([]any)[0].(map[string]any)
	if part["type"] != "message/rfc822" || part["name"] != "forwarded.eml" || part["size"] != float64(len(embedded)) ||
		part["header:Content-Transfer-Encoding:asText"] != "7bit" || part["partId"] == nil || part["subParts"] != nil {
		t.Fatalf("wrong embedded part representation: %v", part)
	}
	partID := part["blobId"].(string)
	download := gatewayRequest(g, http.MethodGet, "/download/"+cfg.AccountID+"/"+partID+"/forwarded.eml", cfg.Token, nil)
	if download.Code != http.StatusOK || download.Body.String() != embedded {
		t.Fatalf("IMAP did not return exact blob bytes: %d", download.Code)
	}
	nested := gatewayCalls(t, g, cfg.Token,
		[3]any{"Email/parse", object{"accountId": cfg.AccountID, "blobIds": []string{partID},
			"properties": []string{"subject", "bcc"}}, "parse"})[0]
	inner := nested.Args["parsed"].(map[string]any)[partID].(map[string]any)
	if inner["subject"] != "Embedded fixture" || !reflect.DeepEqual(inner["bcc"], []any{map[string]any{"name": nil, "email": "historical@example.test"}}) {
		t.Fatalf("encapsulated header metadata: %v", inner)
	}

	select {
	case smtpWire := <-relay.received:
		message, failure := parseMIME([]byte(strings.ReplaceAll(smtpWire, "\r\n..", "\r\n.")), "e-forwarded")
		if failure != "" || len(message.attachments) != 1 || !bytes.Equal(message.attachments[0].Octets, []byte(embedded)) {
			t.Fatalf("SMTP did not transmit the original message: %s", failure)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SMTP fixture did not receive DATA")
	}
	if err := <-relay.done; err != nil {
		t.Fatal(err)
	}
}

func TestDraftEmbeddedMessageRejectsNonTransportableBlobs(t *testing.T) {
	for _, test := range []struct{ name, wire string }{
		{"missing terminal CRLF", "Subject: test\r\n\r\nlast"},
		{"line feed only", "Subject: test\n\nbody\r\n"},
		{"invalid UTF-8", "Subject: \xff\r\n\r\nbody\r\n"},
		{"embedded nul", "Subject: test\r\n\r\nA\x00B\r\n"},
		{"overlong line", "Subject: test\r\n\r\n" + strings.Repeat("a", 999) + "\r\n"},
		{"header-only wire without separator", "Subject: test\r\n"},
		{"overlong header block", "Subject: Test\r\n" + strings.Repeat("X-Many: value\r\n", maxMIMEHeader/10) + "\r\n"},
		{"bad header syntax", "Illegal header line\r\n\r\nbody\r\n"},
		{"missing identifying header", "X-Test: ok\r\n\r\nbody\r\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, valid := embeddedMessageTransport([]byte(test.wire)); valid {
				t.Fatal("invalid embedded message was accepted")
			}
		})
	}
	const line = "Subject: boundary\r\n"
	repeated := strings.Repeat(line, (maxMIMEHeader-500)/len(line))
	remaining := maxMIMEHeader - len(repeated) - len("X: \r\n\r\n")
	atLimit := repeated + "X: " + strings.Repeat("a", remaining)
	_, valid := embeddedMessageTransport([]byte(atLimit + "\r\n\r\n"))
	_, overLimit := embeddedMessageTransport([]byte(atLimit + "a\r\n\r\n"))
	if !valid || overLimit {
		t.Fatal("embedded header budget must include the terminating CRLFs")
	}
	build := func(typ, blobID string, reader func(string) ([]byte, string)) ([]byte, object) {
		const sender = "sender@example.test"
		input := draftFixture("drafts", sender)
		input["bodyStructure"] = object{"type": typ, "blobId": blobID}
		raw, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		draft, failure := makeDraft(raw, time.Now(), func(email string) bool { return sender == email }, reader)
		return draft.raw, failure
	}
	wire, failure := build("message/rfc822", "message", func(string) ([]byte, string) {
		return []byte("Subject: test\r\n\r\nbody\r\n"), ""
	})
	if failure != nil || !bytes.HasSuffix(wire, []byte("\r\n\r\nSubject: test\r\n\r\nbody\r\n")) {
		t.Fatalf("explicit embedded root: %v", failure)
	}
	for _, test := range []struct{ kind, embedded string }{
		{"message/rfc822", "Subject: ASCII\r\nContent-Transfer-Encoding: 8bit\r\n\r\nCaf\xc3\xa9\r\n"},
		{"message/global", "Subject: Terve ää\r\n\r\nbody\r\n"},
	} {
		wire, failure := build(test.kind, "message", func(string) ([]byte, string) {
			return []byte(test.embedded), ""
		})
		if failure != nil || !bytes.Contains(wire, []byte("Content-Transfer-Encoding: 8bit\r\n")) ||
			!bytes.HasSuffix(wire, []byte(test.embedded)) {
			t.Fatalf("embedded %s changed its 8-bit source: %v", test.kind, failure)
		}
	}
	for _, test := range []struct{ typ, blobFailure, wire, want string }{
		{"message/rfc822", "", "not a message", "invalidProperties"},
		{"message/rfc822", "notFound", "", "blobNotFound"},
		{"message/global", "", "Subject: ASCII\r\n\r\nplain\r\n", "invalidProperties"},
		{"message/rfc822", "", "Subject: Terve ää\r\n\r\nbody\r\n", "invalidProperties"},
	} {
		wire, failure := build(test.typ, "message", func(string) ([]byte, string) { return []byte(test.wire), test.blobFailure })
		if wire != nil || failure["type"] != test.want {
			t.Fatalf("invalid embedded blob: %v", failure)
		}
	}
}
