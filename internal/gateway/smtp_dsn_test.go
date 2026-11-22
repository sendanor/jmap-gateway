package gateway

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"
)

func TestDSNParameterValidation(t *testing.T) {
	const recipient = "to+dsn@example.test"
	for _, test := range []struct {
		key, value, recipient string
	}{
		{"RET", "something", ""},
		{"RET", "FULL", recipient},
		{"ENVID", "id", recipient},
		{"ENVID", "", ""},
		{"ENVID", "x\r\nDATA", ""},
		{"ENVID", strings.Repeat("+", 34), ""},
		{"NOTIFY", "SUCCESS", ""},
		{"NOTIFY", "NEVER,FAILURE", recipient},
		{"NOTIFY", "SUCCESS,success", recipient},
		{"NOTIFY", "ſUCCESS", recipient},
		{"ORCPT", "rfc822;" + recipient, ""},
		{"ORCPT", "rfc822 " + recipient, recipient},
		{"ORCPT", "rfc822;different@example.test", recipient},
		{"ORCPT", "utf-8;" + recipient, recipient},
		{"SIZE", "8000", ""},
	} {
		if _, valid := dsnParameters(map[string]*string{test.key: &test.value}, test.recipient); valid {
			t.Fatalf("accepted invalid %s parameter", test.key)
		}
	}
	hdrs := "HDRS"
	if _, ok := dsnParameters(map[string]*string{"RET": &hdrs, "ret": &hdrs}, ""); ok {
		t.Fatal("accepted case-insensitive duplicate")
	}
	never := "never"
	if got, ok := dsnParameters(map[string]*string{"notify": &never}, recipient); !ok || got["NOTIFY"] != "NEVER" {
		t.Fatalf("NOTIFY=NEVER was not accepted: %v", got)
	}
}

func TestSubmissionDSNOverTLS(t *testing.T) {
	cfg := testConfig(t)
	cert, ca := testTLS(t)
	cfg.IMAP.Address, _ = serveTestIMAP(t, cfg.IMAP, cert, imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapUIDPlus: {}}, nil)
	cfg.IMAP.CAFile, cfg.SMTP.CAFile = ca, ca
	addr, unsupported := serveTestSMTP(t, cfg.SMTP, cert, "")
	cfg.SMTP.Address = addr
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	call := func(method string, args object) object {
		t.Helper()
		args["accountId"] = cfg.AccountID
		result := gatewayCalls(t, g, cfg.Token, [3]any{method, args, "dsn"})[0]
		if result.Name != method {
			t.Fatalf("%s returned %v", method, result)
		}
		return result.Args
	}
	extensions := func() object {
		account := g.session["accounts"].(object)[cfg.AccountID].(object)
		return account["accountCapabilities"].(object)[submissionCapability].(object)["submissionExtensions"].(object)
	}
	if len(extensions()) != 0 {
		t.Fatal("DSN capability was enabled by default")
	}
	draft := draftFixture(mailboxID(cfg.AccountID, "Drafts"), cfg.IdentityEmail)
	created := call("Email/set", object{"create": object{"draft": draft}})
	email := created["created"].(map[string]any)["draft"].(map[string]any)["id"]
	recipient := "to+dsn@example.test"
	identity := cfg.IdentityEmail
	envid, ret, notify, orcpt := "ref =+ 7", "hdrs", "failure,success", "RFC822;"+recipient
	envelope := testEnvelope(identity, recipient, "plain@example.test")
	envelope.From.Parameters = map[string]*string{"envid": &envid, "RET": &ret}
	envelope.To[0].Parameters = map[string]*string{"notIFY": &notify, "ORCPT": &orcpt}
	submit := func() object {
		return call("EmailSubmission/set", object{"create": object{
			"send": object{"emailId": email, "identityId": identityID, "envelope": envelope},
		}})
	}
	rejected := func(code string) {
		t.Helper()
		outcome := submit()
		if failure := outcome["notCreated"].(map[string]any)["send"].(map[string]any); failure["type"] != code || len(g.ledger.records) != 0 {
			t.Fatalf("DSN request did not fail safely: %v", failure)
		}
	}
	rejected("invalidProperties")
	reopen := func() {
		t.Helper()
		if err := g.Close(); err != nil {
			t.Fatal(err)
		}
		g, err = New(cfg)
		if err != nil {
			t.Fatal(err)
		}
	}
	cfg.SMTPDeliveryNotifications = true
	reopen()
	if !reflect.DeepEqual(extensions()["DSN"], []string{}) {
		t.Fatalf("unexpected advertised extensions: %v", extensions())
	}
	rejected("forbiddenToSend")
	if err := <-unsupported.done; err != nil || len(unsupported.mailFrom) != 0 || len(unsupported.received) != 0 {
		t.Fatalf("missing DSN was discovered too late: %v", err)
	}

	addr, relay := serveTestSMTP(t, cfg.SMTP, cert, "dsn")
	cfg.SMTP.Address = addr
	reopen()
	outcome := submit()
	submission := outcome["created"].(map[string]any)["send"].(map[string]any)["id"]
	if err := <-relay.done; err != nil {
		t.Fatal(err)
	}
	if got := <-relay.mailFrom; got != "FROM:<"+identity+"> ENVID=ref+20+3D+2B+207 RET=HDRS" {
		t.Fatalf("SMTP MAIL parameters: %s", got)
	}
	if got := <-relay.rcptTo; got != "TO:<"+recipient+"> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;to+2Bdsn@example.test" {
		t.Fatalf("SMTP RCPT parameters: %s", got)
	}
	if got := <-relay.rcptTo; got != "TO:<plain@example.test>" || len(relay.received) != 1 {
		t.Fatalf("SMTP recipient parameters leaked to another recipient: %s", got)
	}
	reopen()
	record := call("EmailSubmission/get", object{"ids": []any{submission}})["list"].([]any)[0].(map[string]any)
	wireEnvelope := record["envelope"].(map[string]any)
	from := wireEnvelope["mailFrom"].(map[string]any)
	recipients := wireEnvelope["rcptTo"].([]any)
	if !reflect.DeepEqual(from["parameters"], map[string]any{"ENVID": envid, "RET": "HDRS"}) ||
		!reflect.DeepEqual(recipients[0].(map[string]any)["parameters"], map[string]any{"NOTIFY": "SUCCESS,FAILURE", "ORCPT": "rfc822;" + recipient}) ||
		recipients[1].(map[string]any)["parameters"] != nil {
		t.Fatalf("DSN parameters were not restored as decoded JMAP values: %v", record)
	}
	status, _ := record["deliveryStatus"].(map[string]any)
	if !reflect.DeepEqual(status, map[string]any{
		recipient:            map[string]any{"smtpReply": "250 2.1.5 Recipient accepted eligible for relay", "delivered": "unknown", "displayed": "unknown"},
		"plain@example.test": map[string]any{"smtpReply": "251 2.1.5 Will forward", "delivered": "unknown", "displayed": "unknown"},
	}) {
		t.Fatalf("SMTP relay replies were not restored after restart: %v", status)
	}
	notify = "SUCCESS,FAILURE"
	if result := submit(); result["created"].(map[string]any)["send"].(map[string]any)["id"] != submission {
		t.Fatalf("equivalent retry was not deduplicated: %v", result)
	}
	notify = "NEVER"
	if result := submit(); result["notCreated"].(map[string]any)["send"].(map[string]any)["type"] != "invalidProperties" {
		t.Fatalf("conflicting retry was accepted: %v", result)
	}
}

func TestLedgerRejectsUnalignedDSNOptions(t *testing.T) {
	dir := testConfig(t).StateDir
	saved := `{"Account":"account","Records":{"key":{"ID":"submission","EmailID":"email","IdentityID":"sender","From":"from@example.test","To":"to@example.test","DSN":{},"SendAt":"2026-11-22T12:00:00Z","Status":"accepted"}}}`
	if err := os.WriteFile(filepath.Join(dir, "submissions.json"), []byte(saved), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := openLedger(dir, "account"); err == nil || err.Error() != "invalid submission record" {
		t.Fatalf("unexpected invalid ledger response: %v", err)
	}
}
