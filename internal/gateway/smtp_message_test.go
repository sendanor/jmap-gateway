package gateway

import (
	"context"
	"net"
	"net/smtp"
	"net/textproto"
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"
)

func TestSMTPNegotiatesRequiredParameters(t *testing.T) {
	const sender = "sender@example.test"
	const recipient = "recipient@example.test"
	const from = "From: " + sender + "\r\nTo: " + recipient + "\r\n"
	const latin = from + "Subject: Eight-bit\r\n\r\ncaf\xe9\r\n"
	const international = from + "Subject: Terve ää\r\n\r\nBody\r\n"
	global := "MIME-Version: 1.0\r\nContent-Type: message/global\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
		string(draftBase64([]byte(international)))
	for _, test := range []struct{ name, extensions, raw, params, unavailable string }{
		{"seven bit to extended server", "smtputf8", from + "Subject: encoded\r\n\r\nbody\r\n", "", ""},
		{"eight-bit body", "8bitmime", latin, " BODY=8BITMIME", ""},
		{"UTF-8 message header", "smtputf8", international, " SMTPUTF8 BODY=8BITMIME", ""},
		{"base64-encapsulated UTF-8", "smtputf8", from + global, " SMTPUTF8", ""},
		{"missing 8BITMIME", "", latin, "", "8BITMIME"},
		{"missing SMTPUTF8", "8bitmime", international, "", "SMTPUTF8"},
		{"broken SMTPUTF8 advertisement", "utf8-without-8bit", international, "", "8BITMIME"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := testConfig(t)
			cert, ca := testTLS(t)
			cfg.SMTP.CAFile = ca
			remote, fixture := serveTestSMTP(t, cfg.SMTP, cert, test.extensions)
			cfg.SMTP.Address = remote
			tlsConfig, err := upstreamTLS(cfg.SMTP)
			if err != nil {
				t.Fatal(err)
			}
			prepared, failure := prepareSubmission([]byte(test.raw), sender, nil)
			if failure != nil {
				t.Fatalf("message preparation: %v", failure)
			}
			outcome := sendSMTP(context.Background(), cfg.SMTP, tlsConfig, sender, prepared.recipients, prepared.wire, prepared.transport, nil)
			if err := <-fixture.done; err != nil {
				t.Fatal(err)
			}
			if test.unavailable != "" {
				if outcome.failure != "forbiddenToSend" || !strings.Contains(outcome.description, test.unavailable) || outcome.uncertain ||
					len(fixture.mailFrom) != 0 || len(fixture.received) != 0 {
					t.Fatalf("unsupported SMTP transport began a transaction: %+v", outcome)
				}
				return
			}
			if outcome.failure != "" || len(fixture.mailFrom) != 1 || len(fixture.received) != 1 {
				t.Fatalf("supported SMTP transport failed: %+v", outcome)
			}
			if command := <-fixture.mailFrom; command != "FROM:<"+sender+">"+test.params {
				t.Fatalf("wrong MAIL options: %q", command)
			}
			if wire := <-fixture.received; wire != test.raw {
				t.Fatal("SMTP changed the wire bytes")
			}
		})
	}
}

func TestSMTPInspectsEncapsulatedAndPartHeaders(t *testing.T) {
	const header = "From: sender@example.test\r\nTo: recipient@example.test\r\nMIME-Version: 1.0\r\n"
	part := "Content-Type: text/plain\r\nContent-Description: Terve ää\r\n\r\nBody"
	outer := header + "Content-Type: multipart/mixed; boundary=fixture\r\n\r\n--fixture\r\n" + part + "\r\n--fixture--\r\n"
	prepared, failure := prepareSubmission([]byte(outer), "sender@example.test", nil)
	if failure != nil || prepared.transport != (smtpTransport{eightBit: true, utf8: true}) {
		t.Fatalf("nested MIME headers: %+v %v", prepared.transport, failure)
	}
	global := header + "Content-Type: message/global\r\nContent-Transfer-Encoding: base64\r\n\r\n"
	for _, body := range []string{"!!!!\r\n", string(draftBase64([]byte("invalid embedded message")))} {
		if _, failure := prepareSubmission([]byte(global+body), "sender@example.test", nil); failure["type"] != "invalidEmail" {
			t.Fatalf("malformed embedded mail accepted: %v", failure)
		}
	}
	budget := 1
	if _, _, ok := inspectSMTPMessage([]byte(outer), 0, &budget); ok {
		t.Fatal("SMTP inspection ignored its budget")
	}
}

func TestSMTPMailRejectsUnsafeSenderAndWriteFailure(t *testing.T) {
	if err := smtpMail(nil, "sender@example.test\r\n", ""); err == nil {
		t.Fatal("malformed sender passed validation")
	}
	local, peer := net.Pipe()
	defer local.Close()
	_ = peer.Close()
	client := &smtp.Client{Text: textproto.NewConn(local)}
	if err := smtpMail(client, "sender@example.test", ""); err == nil {
		t.Fatal("SMTP command reported success after connection closed")
	}
}

func TestSMTPUpgradeAllowsRetryWithoutDuplicateReservation(t *testing.T) {
	cfg := testConfig(t)
	cfg.DraftsMailbox = "Drafts"
	cert, trusted := testTLS(t)
	cfg.IMAP.Address, _ = serveTestIMAP(t, cfg.IMAP, cert, imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapUIDPlus: {}}, nil)
	cfg.IMAP.CAFile, cfg.SMTP.CAFile = trusted, trusted
	var relay *smtpFixture
	cfg.SMTP.Address, relay = serveTestSMTP(t, cfg.SMTP, cert, "8bitmime")
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if g != nil {
			_ = g.Close()
		}
	}()

	draft := draftFixture(mailboxID(cfg.AccountID, "Drafts"), cfg.IdentityEmail)
	draft["textBody"] = []object{{"partId": "text", "type": "text/plain"}}
	draft["bodyValues"] = object{"text": object{"value": "Body"}}
	delete(draft, "subject")
	draft["header:Subject"] = " Välitetty"
	got := gatewayCalls(t, g, cfg.Token,
		[3]any{"Email/set", object{"accountId": cfg.AccountID, "create": object{"draft": draft}}, "create"},
		[3]any{"EmailSubmission/set", object{"accountId": cfg.AccountID,
			"create": object{"send": object{"emailId": "#draft", "identityId": identityID}}}, "send"})
	created := got[0].Args["created"].(map[string]any)["draft"].(map[string]any)
	failure := got[1].Args["notCreated"].(map[string]any)["send"].(map[string]any)
	if failure["type"] != "forbiddenToSend" || !strings.Contains(failure["description"].(string), "SMTPUTF8") ||
		len(g.ledger.records) != 0 || len(relay.mailFrom) != 0 {
		t.Fatalf("blocked transport left a submission reservation: %v", failure)
	}
	if err := <-relay.done; err != nil {
		t.Fatal(err)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	cfg.SMTP.Address, relay = serveTestSMTP(t, cfg.SMTP, cert, "smtputf8")
	g, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	request := [3]any{"EmailSubmission/set", object{"accountId": cfg.AccountID,
		"create": object{"send": object{"emailId": created["id"], "identityId": identityID}}}, "retry"}
	for range 2 {
		result := gatewayCalls(t, g, cfg.Token, request)[0]
		if result.Args["created"] == nil || len(g.ledger.records) != 1 {
			t.Fatalf("replay after relay upgrade: %v", result)
		}
	}
	if err := <-relay.done; err != nil {
		t.Fatal(err)
	}
	if len(relay.mailFrom) != 1 || len(relay.received) != 1 {
		t.Fatal("relay did not receive exactly one transport transaction")
	}
}
