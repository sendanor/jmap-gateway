package gateway

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
)

func TestSubmissionKeyDependsOnMessageBytes(t *testing.T) {
	const sender = "sender@example.test"
	const raw = "From: " + sender + "\r\nTo: recipient@example.test\r\n" +
		"Message-ID: <0123456789abcdef0123456789abcdef@jmap.invalid>\r\n\r\n"
	first, failure := prepareSubmission([]byte(raw+"first\r\n"), sender, nil)
	if failure != nil {
		t.Fatal(failure)
	}
	second, failure := prepareSubmission([]byte(raw+"second\r\n"), sender, nil)
	if failure != nil || first.key == second.key || first.legacyKey == "" || first.legacyKey != second.legacyKey {
		t.Fatalf("separate content reused a reservation: %q, %q, %v", first.key, second.key, failure)
	}
	if _, failure := prepareSubmission([]byte(raw+"binary\x00body\r\n"), sender, nil); failure["type"] != "invalidEmail" {
		t.Fatalf("message containing NUL was accepted for SMTP DATA: %v", failure)
	}
}

func TestStoredEmailSubmissionReplayAcrossMailboxes(t *testing.T) {
	for _, smtpFault := range []string{"", "lost-reply"} {
		t.Run("smtp-"+smtpFault, func(t *testing.T) {
			config := testConfig(t)
			cert, ca := testTLS(t)
			caps := imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapUIDPlus: {}}
			imapAddress, user := serveTestIMAP(t, config.IMAP, cert, caps, nil)
			config.IMAP.Address, config.IMAP.CAFile, config.SMTP.CAFile = imapAddress, ca, ca
			smtpAddress, relay := serveTestSMTP(t, config.SMTP, cert, smtpFault)
			config.SMTP.Address = smtpAddress
			g, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = g.Close() }()

			raw := "From: " + config.IdentityEmail + "\r\nTo: first@example.test\r\n" +
				"Date: Sun, 22 Nov 2026 12:00:00 +0000\r\nSubject: Stored fixture\r\n\r\nOriginal text.\r\n"
			appendEmail := func(folder, content string) string {
				t.Helper()
				data, err := user.Append(folder, strings.NewReader(content), &imap.AppendOptions{Time: time.Now()})
				if err != nil {
					t.Fatal(err)
				}
				return emailID(mailboxID(config.AccountID, folder), data.UIDValidity, data.UID)
			}
			original := appendEmail("INBOX", raw)
			copy := appendEmail("Plain", raw)
			unauthorized := appendEmail("INBOX", strings.Replace(raw, config.IdentityEmail, "someone@example.test", 1))
			send := func(id string) object {
				t.Helper()
				response := gatewayCalls(t, g, config.Token, [3]any{"EmailSubmission/set", object{
					"accountId": config.AccountID,
					"create":    object{"send": object{"emailId": id, "identityId": identityID}},
				}, "send"})[0]
				if response.Name != "EmailSubmission/set" {
					t.Fatalf("submit returned %v", response)
				}
				return response.Args
			}
			if result := send(unauthorized); result["notCreated"].(map[string]any)["send"].(map[string]any)["type"] != "forbiddenFrom" ||
				len(g.ledger.records) != 0 {
				t.Fatalf("unauthorized header reached the submission ledger: %v", result)
			}
			accepted := send(original)
			select {
			case err := <-relay.done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("submission never reached SMTP: %v", accepted)
			}
			select {
			case got := <-relay.received:
				if got != raw {
					t.Fatalf("SMTP received modified stored message: %q", got)
				}
			default:
				t.Fatal("SMTP received no DATA")
			}
			if err := g.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			g = reopened
			replayed := send(copy)
			if smtpFault == "lost-reply" {
				failure := replayed["notCreated"].(map[string]any)["send"].(map[string]any)
				if failure["type"] != "serverFail" || !strings.Contains(failure["description"].(string), "blocked from resubmission") {
					t.Fatalf("pending message fingerprint did not prevent retry after restart: %v", replayed)
				}
			} else if accepted["created"] == nil || !reflect.DeepEqual(replayed["created"], accepted["created"]) {
				t.Fatalf("replayed message created another submission: %v, %v", accepted, replayed)
			}
			if len(g.ledger.records) != 1 {
				t.Fatalf("expected one immutable submission reservation, got %d", len(g.ledger.records))
			}
		})
	}
}
