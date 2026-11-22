package gateway

import (
	"bytes"
	"encoding/json"
	"net/mail"
	"reflect"
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"
)

func TestSubmissionEnvelopesOverTLS(t *testing.T) {
	for _, scenario := range []struct {
		name, smtpFault, code string
		explicit              bool
	}{
		{name: "derived"}, {name: "explicit", explicit: true},
		{name: "permanent recipient failure", smtpFault: "selective", code: "invalidRecipients", explicit: true},
		{name: "temporary recipient failure", smtpFault: "temporary", code: "serverUnavailable", explicit: true},
		{name: "relay size limit", smtpFault: "size", code: "tooLarge"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			config := testConfig(t)
			cert, ca := testTLS(t)
			config.DraftsMailbox = "Drafts"
			config.IMAP.Address, _ = serveTestIMAP(t, config.IMAP, cert, imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapUIDPlus: {}}, nil)
			config.IMAP.CAFile, config.SMTP.CAFile = ca, ca
			smtpAddress, relay := serveTestSMTP(t, config.SMTP, cert, scenario.smtpFault)
			config.SMTP.Address = smtpAddress
			g, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = g.Close() }()

			draft := draftFixture(mailboxID(config.AccountID, "Drafts"), config.IdentityEmail)
			draft["to"] = []address{{Email: "to@example.test"}, {Email: "extra@example.test"}}
			draft["cc"] = []address{{Email: "to@EXAMPLE.TEST"}, {Email: "cc@example.test"}}
			draft["bcc"] = []address{{Email: "secret@example.test"}}
			draft["textBody"] = []object{{"partId": "text", "type": "text/plain"}}
			draft["bodyValues"] = object{"text": object{"value": "Bcc: this is part of the body"}}
			expected := []string{"to@example.test", "extra@example.test", "cc@example.test", "secret@example.test"}
			submission := object{"emailId": "#draft", "identityId": identityID}
			if scenario.explicit {
				expected = []string{"forward@example.test", "other@example.test"}
				switch scenario.smtpFault {
				case "selective":
					expected = []string{"forward@example.test", "reject-one@example.test", "reject-two@example.test"}
				case "temporary":
					expected = []string{"forward@example.test", "retry-one@example.test"}
				}
				submission["envelope"] = testEnvelope(config.IdentityEmail, expected...)
			}
			flow := gatewayCalls(t, g, config.Token,
				[3]any{"Email/set", object{"accountId": config.AccountID, "create": object{"draft": draft}}, "draft"},
				[3]any{"EmailSubmission/set", object{"accountId": config.AccountID, "create": object{"send": submission}}, "submit"})
			if flow[0].Name != "Email/set" || flow[0].Args["created"] == nil || flow[1].Name != "EmailSubmission/set" {
				t.Fatalf("failed to run mail flow: %v", flow)
			}
			if err := <-relay.done; err != nil {
				t.Fatal(err)
			}
			if scenario.code != "" {
				failure := flow[1].Args["notCreated"].(map[string]any)["send"].(map[string]any)
				if failure["type"] != scenario.code || len(g.ledger.records) != 0 || len(relay.received) != 0 {
					t.Fatalf("SMTP failure sent DATA or left a reservation: %v", failure)
				}
				if scenario.smtpFault == "selective" && !reflect.DeepEqual(failure["invalidRecipients"], []any{"reject-one@example.test", "reject-two@example.test"}) {
					t.Fatalf("incorrect rejected set: %v", failure)
				}
				if scenario.smtpFault == "size" && failure["maxSize"] != float64(80) {
					t.Fatalf("incorrect upstream maximum: %v", failure)
				}
				return
			}
			raw := <-relay.received
			wire, err := mail.ReadMessage(strings.NewReader(raw))
			if err != nil || len(wire.Header["Bcc"]) != 0 || !strings.Contains(raw, "\r\nBcc: this is part of the body") ||
				wire.Header.Get("Cc") == "" || wire.Header.Get("To") == "" {
				t.Fatalf("SMTP modified fields beyond the Bcc header: %q %v", raw, err)
			}
			submissionID := flow[1].Args["created"].(map[string]any)["send"].(map[string]any)["id"].(string)
			draftID := flow[0].Args["created"].(map[string]any)["draft"].(map[string]any)["id"].(string)
			if err := g.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			g = reopened
			submission["emailId"] = draftID
			stored := gatewayCalls(t, g, config.Token,
				[3]any{"EmailSubmission/get", object{"accountId": config.AccountID, "ids": []string{submissionID}}, "get"},
				[3]any{"EmailSubmission/set", object{"accountId": config.AccountID, "create": object{"retry": submission}}, "retry"},
				[3]any{"Email/get", object{"accountId": config.AccountID, "ids": []string{draftID}, "properties": []string{"bcc"}}, "read"})
			envelope := stored[0].Args["list"].([]any)[0].(map[string]any)["envelope"].(map[string]any)
			var recipients []string
			for _, item := range envelope["rcptTo"].([]any) {
				recipients = append(recipients, item.(map[string]any)["email"].(string))
			}
			if !reflect.DeepEqual(recipients, expected) ||
				stored[1].Args["created"].(map[string]any)["retry"].(map[string]any)["id"] != submissionID ||
				stored[2].Args["list"].([]any)[0].(map[string]any)["bcc"].([]any)[0].(map[string]any)["email"] != "secret@example.test" {
				t.Fatalf("restart changed the submission envelope or original draft: %v", stored)
			}
			submission["envelope"] = testEnvelope(config.IdentityEmail, "different@example.test")
			conflict := gatewayCalls(t, g, config.Token, [3]any{"EmailSubmission/set", object{"accountId": config.AccountID, "create": object{"retry": submission}}, "retry"})[0]
			if failure := conflict.Args["notCreated"].(map[string]any)["retry"].(map[string]any); failure["type"] != "invalidProperties" {
				t.Fatalf("conflicting replay did not report envelope mismatch: %v", conflict)
			}
		})
	}
}

func testEnvelope(sender string, recipients ...string) smtpEnvelope {
	result := smtpEnvelope{From: envelopeAddress{Email: sender}}
	for _, recipient := range recipients {
		result.To = append(result.To, envelopeAddress{Email: recipient})
	}
	return result
}

func TestSubmissionEnvelopeValidation(t *testing.T) {
	const sender = "sender@example.test"
	const base = "From: " + sender + "\r\nMessage-ID: <0123456789abcdef0123456789abcdef@jmap.invalid>\r\nContent-Type: text/plain\r\n"
	for _, tc := range []struct {
		name     string
		envelope smtpEnvelope
		code     string
	}{
		{"empty sender", testEnvelope("", "ok@example.test"), "invalidProperties"},
		{"different sender", testEnvelope("other@example.test", "ok@example.test"), "forbiddenMailFrom"},
		{"empty recipient list", testEnvelope(sender), "noRecipients"},
		{"invalid recipient", testEnvelope(sender, "ü@example.test", "no-domain"), "invalidRecipients"},
		{"unsupported sender parameter", smtpEnvelope{From: envelopeAddress{Email: sender, Parameters: map[string]*string{"SMTPUTF8": nil}}}, "invalidProperties"},
		{"unsupported recipient parameter", smtpEnvelope{From: envelopeAddress{Email: sender}, To: []envelopeAddress{{Email: "ok@example.test", Parameters: map[string]*string{"NOTIFY": nil}}}}, "invalidProperties"},
		{"recipient limit", testEnvelope(sender, make([]string, maxSubmissionRecipients+1)...), "tooManyRecipients"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, failure := tc.envelope.recipients(sender); failure["type"] != tc.code {
				t.Errorf("got %v, want %s", failure, tc.code)
			}
		})
	}
	original := []byte(base + "Sender: other@example.test\r\nTo: group: first@example.test;\r\nBcc:\r\nBCC : hidden@example.test,\r\n\tsecond@example.test\r\n\r\nBcc: body stays\r\n")
	prepared, failure := prepareSubmission(original, sender, nil)
	want := []string{"first@example.test", "hidden@example.test", "second@example.test"}
	if failure != nil || !reflect.DeepEqual(prepared.recipients, want) ||
		!bytes.Equal(prepared.wire, []byte(base+"Sender: other@example.test\r\nTo: group: first@example.test;\r\n\r\nBcc: body stays\r\n")) {
		t.Fatalf("unexpected header derivation or redaction: %v, %v, %q", failure, prepared.recipients, prepared.wire)
	}
	for _, tc := range []struct{ headers, code string }{
		{"", "noRecipients"},
		{"To: ü@bad_domain.test\r\n", "invalidRecipients"},
		{"To: first@example.test\r\nSender: malformed\r\n", "invalidEmail"},
	} {
		if _, failure := prepareSubmission([]byte(base+tc.headers+"\r\n"), sender, nil); failure["type"] != tc.code {
			t.Fatalf("invalid draft headers returned %v, want %s", failure, tc.code)
		}
	}
	malformed := []byte(base + "Bad Header: malformed\r\nBcc: hidden@example.test\r\n\r\n")
	if _, failure := prepareSubmission(malformed, sender, nil); failure["type"] != "invalidEmail" {
		t.Fatalf("malformed message headers returned %v", failure)
	}
	op := operation{g: &Gateway{config: Config{IdentityEmail: sender}}}
	input, err := json.Marshal(object{"emailId": emailID("drafts", 1, 1), "identityId": identityID,
		"envelope": testEnvelope(sender)})
	if err != nil {
		t.Fatal(err)
	}
	if _, failure := op.submit(input); failure["type"] != "noRecipients" {
		t.Fatalf("submission with explicit empty recipient list returned %v", failure)
	}
}
