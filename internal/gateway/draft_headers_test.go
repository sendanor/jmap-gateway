package gateway

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
)

func TestDraftHeaderWritesAcrossIMAPAndSMTP(t *testing.T) {
	cfg := testConfig(t)
	cfg.DraftsMailbox = "Drafts"
	cert, ca := testTLS(t)
	caps := imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapUIDPlus: {}}
	cfg.IMAP.Address, _ = serveTestIMAP(t, cfg.IMAP, cert, caps, nil)
	cfg.IMAP.CAFile, cfg.SMTP.CAFile = ca, ca
	var relay *smtpFixture
	cfg.SMTP.Address, relay = serveTestSMTP(t, cfg.SMTP, cert, "")
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	input := draftFixture(mailboxID(cfg.AccountID, "Drafts"), cfg.IdentityEmail)
	delete(input, "from")
	delete(input, "to")
	input["header:From"] = " Authorized <" + cfg.IdentityEmail + ">"
	input["header:To:asGroupedAddresses"] = []object{
		{"name": nil, "addresses": []object{}},
		{"name": "Tiimi", "addresses": []object{{"email": "recipient@example.test", "name": "Ääni"}}},
		{"name": nil, "addresses": []object{{"email": "other@example.test"}}},
	}
	input["subject"] = " =?UTF-8?Q?literal?= " + strings.Repeat("ä🍀", 25)
	input["header:X-Trace:all"] = []string{"first", " second\r\n\tcontinued"}
	input["header:List-Unsubscribe:asURLs"] = []string{"https://example.test/unsubscribe", "mailto:leave@example.test"}
	input["header:List-Id:asText"] = "Luettelo"
	input["messageId"] = []string{"message@example.test"}
	input["references"] = []string{"one@example.test", "two@example.test"}
	input["sentAt"] = "2026-11-22T20:15:00+02:00"
	input["sender"] = []object{{"email": cfg.IdentityEmail}}
	input["header:MIME-Version"] = " 1.0"
	input["header:X-Omitted"] = nil
	input["header:X-Empty:all"] = []string{}
	input["textBody"] = []object{{"partId": "text", "type": "text/plain"}}
	input["bodyValues"] = object{"text": object{"value": "Body"}}
	props := []string{"header:X-Trace:all", "header:List-Unsubscribe:asURLs", "header:List-Id:asText",
		"header:To:asGroupedAddresses", "header:X-Omitted", "header:X-Empty:all", "header:MIME-Version:all",
		"subject", "sentAt", "messageId", "references", "sender"}
	account := cfg.AccountID
	flow := gatewayCalls(t, g, cfg.Token,
		[3]any{"Email/set", object{"accountId": account, "create": object{"draft": input}}, "create"},
		[3]any{"Email/get", object{"accountId": account, "ids": []string{"#draft"}, "properties": props}, "read"},
		[3]any{"EmailSubmission/set", object{"accountId": account, "create": object{"send": object{"emailId": "#draft", "identityId": identityID}}}, "send"})
	records, ok := flow[1].Args["list"].([]any)
	if !ok || len(records) != 1 || flow[2].Args["created"] == nil {
		t.Fatalf("draft header flow: %v", flow)
	}
	read := records[0].(map[string]any)
	wantProperties := object{
		"header:X-Trace:all":             []any{"first", " second\r\n\tcontinued"},
		"header:List-Id:asText":          "Luettelo",
		"header:List-Unsubscribe:asURLs": []any{"https://example.test/unsubscribe", "mailto:leave@example.test"},
		"header:X-Omitted":               nil,
		"header:X-Empty:all":             []any{},
		"header:MIME-Version:all":        []any{" 1.0"},
		"subject":                        input["subject"],
		"sentAt":                         input["sentAt"],
		"messageId":                      []any{"message@example.test"},
		"references":                     []any{"one@example.test", "two@example.test"},
		"sender":                         []any{map[string]any{"email": cfg.IdentityEmail, "name": nil}},
	}
	for property, want := range wantProperties {
		if !reflect.DeepEqual(read[property], want) {
			t.Fatalf("%s = %#v, want %#v", property, read[property], want)
		}
	}
	group := read["header:To:asGroupedAddresses"].([]any)[0].(map[string]any)
	if group["name"] != "Tiimi" || group["addresses"].([]any)[0].(map[string]any)["name"] != "Ääni" {
		t.Fatalf("grouped address changed: %v", group)
	}
	wire := string(<-relay.received)
	if err := <-relay.done; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(wire, "X-Trace:first\r\nX-Trace: second\r\n\tcontinued\r\n") ||
		!strings.Contains(wire, "Message-Id: <message@example.test>") {
		t.Fatalf("unexpected SMTP headers: %q", wire)
	}
}

func TestDraftHeaderValidation(t *testing.T) {
	const sender = "sender@example.test"
	allowed := func(email string) bool { return email == sender }
	now := time.Date(2026, 11, 25, 12, 30, 0, 0, time.UTC)
	recipients := make([]object, maxSubmissionRecipients+1)
	for i := range recipients {
		recipients[i] = object{"email": "recipient@example.test"}
	}
	for _, test := range []struct {
		name  string
		key   string
		value any
	}{
		{"malformed selector", "header::asText", "hello"},
		{"forbidden known form", "header:List-Id:asDate", "2026-11-22T00:00:00Z"},
		{"duplicate named From", "header:FROM", sender},
		{"top-level MIME structure", "header:Content-Type", " text/plain"},
		{"long name", "header:" + strings.Repeat("A", 998), "value"},
		{"invalid MIME version", "header:MIME-Version", " 2.0"},
		{"repeated header requires array", "header:X-Repeat:all", "one"},
		{"raw must be string", "header:X-Raw", true},
		{"null item", "header:X-Raw:all", []any{nil}},
		{"raw injection", "header:X-Raw", " value\r\nBcc: x@example.test"},
		{"bare newline", "header:X-Raw", " value\n continuation"},
		{"empty fold", "header:X-Raw", " value\r\n"},
		{"overlong first line", "header:X-Raw", strings.Repeat("x", 998)},
		{"overlong continuation", "header:X-Raw", " v\r\n " + strings.Repeat("x", 998)},
		{"typed text control", "header:Comments:asText", "contains\x00NUL"},
		{"invalid date", "sentAt", "yesterday"},
		{"unrepresentable date", "sentAt", "1899-01-01T00:00:00Z"},
		{"address value must be list", "sender", "someone@example.test"},
		{"invalid address", "sender", []object{{"email": "invalid"}}},
		{"address display name injection", "sender", []object{{"email": sender, "name": "bad\r\n value"}}},
		{"too many addresses", "cc", recipients},
		{"wrong grouped address shape", "header:To:asGroupedAddresses", true},
		{"invalid group members", "header:To:asGroupedAddresses", []object{{"name": "Group", "addresses": nil}}},
		{"invalid group name", "header:To:asGroupedAddresses", []object{{"name": "", "addresses": []object{}}}},
		{"too many groups", "header:To:asGroupedAddresses", make([]emailAddressGroup, maxSubmissionRecipients+1)},
		{"empty id list", "messageId", []string{}},
		{"invalid id", "messageId", []string{"bad"}},
		{"separator in message-id", "messageId", []string{"one,two@example.test"}},
		{"unsupported international message-id form", "messageId", []string{"ü@example.test"}},
		{"invalid angle encoding", "references", []string{"<x@example.test>"}},
		{"invalid URL", "header:List-Unsubscribe:asURLs", []string{"/path"}},
		{"invalid URL escape", "header:List-Unsubscribe:asURLs", []string{"https://example.test/%xx"}},
		{"unauthorized sender", "sender", []object{{"email": "someone@example.test"}}},
		{"repeated From", "header:From:all", []string{sender, sender}},
		{"invalid raw From", "header:From", "one <>"},
		{"multiple From addresses", "header:From", " <" + sender + ">, <second@example.test>"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fields := object{"from": []object{{"email": sender}}}
			if strings.HasPrefix(test.key, "header:From") && test.key != "header:FROM" {
				delete(fields, "from")
			}
			fields[test.key] = test.value
			if _, failure := draftHeaders(rawArgs(t, fields), now, allowed); failure["type"] != "invalidProperties" {
				t.Fatalf("invalid header passed validation: %v", failure)
			}
		})
	}
	// Multiple otherwise-valid recipient fields can exceed the combined limit.
	for _, item := range recipients {
		item["email"] = "recipient@example.test"
	}
	fields := object{"from": []object{{"email": sender}}, "to": recipients[:maxSubmissionRecipients],
		"cc": recipients[:1]}
	if _, failure := draftHeaders(rawArgs(t, fields), now, allowed); failure["type"] != "invalidProperties" {
		t.Fatalf("combined recipient bound: %v", failure)
	}
	if _, failure := makeDraft(json.RawMessage("null"), now, allowed, nil); failure["type"] != "invalidProperties" {
		t.Fatalf("null draft accepted: %v", failure)
	}
	input := json.RawMessage(`{"from":[{"email":"sender@example.test"}],"mailboxIds":{"drafts":true},"headers":[]}`)
	if _, failure := makeDraft(input, now, allowed, nil); failure["type"] != "invalidProperties" {
		t.Fatalf("structured headers array accepted on Create: %v", failure)
	}
}
