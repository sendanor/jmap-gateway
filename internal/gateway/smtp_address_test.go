package gateway

import (
	"context"
	"net/mail"
	"reflect"
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"
)

func TestInternationalSMTPAddressValidation(t *testing.T) {
	for _, test := range []struct{ address, key string }{
		{"Ääni@bücher.example", "Ääni@xn--bcher-kva.example"},
		{"Ääni@XN--BCHER-KVA.EXAMPLE", "Ääni@xn--bcher-kva.example"},
		{"A\u0308a\u0308ni@example.test", "A\u0308a\u0308ni@example.test"},
		{"ü@example.test", "ü@example.test"},
		{"fake\r\n@example.test", ""},
		{"ü\u0085@example.test", ""},
		{"ü\ufdd0@example.test", ""},
		{"ü\U0001ffff@example.test", ""},
		{"\xff@example.test", ""},
		{"ü@bad_domain.test", ""},
		{"ü@.test", ""},
		{"ü@test.", ""},
		{"ü@e..test", ""},
		{"ü@e-.test", ""},
		{"ü@" + strings.Repeat("a", 64) + ".test", ""},
		{strings.Repeat("ü", 33) + "@example.test", ""},
		{"ü@bücher.example, another@example.test", ""},
		{"ü..a@example.test", ""},
	} {
		got, ok := smtpAddressKey(test.address)
		if got != test.key || ok != (test.key != "") {
			t.Errorf("mailbox %q key = %q, %t, want %q", test.address, got, ok, test.key)
		}
	}
	header := mail.Header{"To": {"Ääni@bücher.example, Ääni@XN--BCHER-KVA.EXAMPLE, ääni@bücher.example"}}
	got, failure := headerRecipients(header)
	if failure != nil || !reflect.DeepEqual(got, []string{"Ääni@bücher.example", "ääni@bücher.example"}) {
		t.Fatalf("derived recipient matching changed local parts: %v %v", got, failure)
	}
}

func TestInternationalRecipientOnlyInEnvelope(t *testing.T) {
	const sender = "sender@example.test"
	const recipient = "ääni@bücher.example"
	const raw = "From: sender@example.test\r\nTo: visible@example.test\r\nSubject: Example\r\n\r\nPlain\r\n"
	prepared, failure := prepareSubmission([]byte(raw), sender, []string{recipient})
	if failure != nil || prepared.transport != (smtpTransport{utf8: true}) || string(prepared.wire) != raw {
		t.Fatalf("UTF-8 envelope with ASCII DATA: %v %v", prepared.transport, failure)
	}
	for _, extensions := range []string{"8bitmime", "smtputf8"} {
		cfg := testConfig(t)
		cert, ca := testTLS(t)
		remote, relay := serveTestSMTP(t, cfg.SMTP, cert, extensions)
		cfg.SMTP.Address, cfg.SMTP.CAFile = remote, ca
		trust, err := upstreamTLS(cfg.SMTP)
		if err != nil {
			t.Fatal(err)
		}
		outcome := sendSMTP(context.Background(), cfg.SMTP, trust, sender, prepared.recipients, prepared.wire, prepared.transport, nil)
		if err := <-relay.done; err != nil {
			t.Fatal(err)
		}
		if extensions == "8bitmime" {
			if outcome.failure != "forbiddenToSend" || len(relay.mailFrom) != 0 {
				t.Fatalf("sent international recipient without SMTPUTF8: %+v", outcome)
			}
			continue
		}
		if outcome.failure != "" || len(relay.mailFrom) != 1 || <-relay.mailFrom != "FROM:<"+sender+"> SMTPUTF8" {
			t.Fatalf("incorrect SMTPUTF8 envelope for ASCII DATA: %+v", outcome)
		}
	}
}

func TestInternationalIdentityAndLedgerOverTLS(t *testing.T) {
	cfg := testConfig(t)
	cfg.DraftsMailbox = "Drafts"
	cfg.IdentityAliases = []string{"lähettäjä@example.test"}
	cert, ca := testTLS(t)
	cfg.IMAP.Address, _ = serveTestIMAP(t, cfg.IMAP, cert, imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapUIDPlus: {}}, nil)
	cfg.IMAP.CAFile, cfg.SMTP.CAFile = ca, ca
	relayAddress, relay := serveTestSMTP(t, cfg.SMTP, cert, "smtputf8")
	cfg.SMTP.Address = relayAddress
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if g != nil {
			_ = g.Close()
		}
	}()
	allowed := cfg.IdentityAliases[0]
	identities := gatewayCalls(t, g, cfg.Token,
		[3]any{"Identity/set", object{"accountId": cfg.AccountID,
			"create": object{"allowed": object{"email": allowed}, "denied": object{"email": "Lähettäjä@example.test"}}}, "identities"})[0].Args
	created := identities["created"].(map[string]any)["allowed"].(map[string]any)["id"]
	if identities["notCreated"].(map[string]any)["denied"].(map[string]any)["type"] != "forbiddenFrom" {
		t.Fatalf("distinct UTF-8 local part was authorized: %v", identities)
	}
	draft := draftFixture(mailboxID(cfg.AccountID, "Drafts"), allowed)
	draft["to"] = []address{{Email: "ääni@example.test"}}
	draft["textBody"] = []object{{"partId": "text", "type": "text/plain"}}
	draft["bodyValues"] = object{"text": object{"value": "Test"}}
	calls := gatewayCalls(t, g, cfg.Token,
		[3]any{"Email/set", object{"accountId": cfg.AccountID, "create": object{"draft": draft}}, "create"},
		[3]any{"EmailSubmission/set", object{"accountId": cfg.AccountID, "create": object{"send": object{"identityId": created, "emailId": "#draft"}}}, "send"})
	if calls[0].Args["created"] == nil || calls[1].Args["created"] == nil {
		t.Fatalf("international draft or submission failed: %v", calls)
	}
	if err := <-relay.done; err != nil {
		t.Fatal(err)
	}
	if len(relay.mailFrom) != 1 || <-relay.mailFrom != "FROM:<"+allowed+"> SMTPUTF8 BODY=8BITMIME" {
		t.Fatal("selected international identity did not reach SMTP")
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	g, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	records := gatewayCalls(t, g, cfg.Token,
		[3]any{"EmailSubmission/get", object{"accountId": cfg.AccountID}, "accepted"})[0].Args
	saved := records["list"].([]any)[0].(map[string]any)["envelope"].(map[string]any)
	if saved["mailFrom"].(map[string]any)["email"] != allowed ||
		saved["rcptTo"].([]any)[0].(map[string]any)["email"] != "ääni@example.test" {
		t.Fatalf("ledger reloaded different addresses: %v", saved)
	}
}
