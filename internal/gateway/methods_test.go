package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
)

func TestUnavailableMailboxMethodsAndGetLimits(t *testing.T) {
	c := testConfig(t)
	g, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	op := operation{g: g, ctx: context.Background(), snapshotFailure: "serverUnavailable"}
	for _, test := range []struct {
		name    string
		args    object
		failure string
	}{
		{"Alien/unknown", object{}, "unknownMethod"},
		{"Email/unknown", object{}, "unknownMethod"},
		{"Email/get", object{}, "invalidArguments"},
		{"Mailbox/get", object{"accountId": c.AccountID}, "serverUnavailable"},
		{"Email/query", object{"accountId": c.AccountID}, "serverUnavailable"},
		{"Email/set", object{"accountId": c.AccountID}, "serverUnavailable"},
		{"Email/get", object{"accountId": c.AccountID, "maxBodyValueBytes": -1}, "invalidArguments"},
		{"Email/get", object{"accountId": c.AccountID, "ids": make([]string, maxGet+1)}, "requestTooLarge"},
	} {
		name, data := op.call(invocation{name: test.name, args: rawArgs(t, test.args)})
		if name != "error" || data["type"] != test.failure {
			t.Errorf("%s returned %s %v", test.name, name, data)
		}
	}
	if methodCapability("Alien/unknown") != "" {
		t.Fatal("unknown method has a capability")
	}
	id := emailID("folder", 1, 1)
	op.snapshot = &snapshot{emails: map[string]*emailMeta{id: {ID: id}}}
	op.snapshotFailure = ""
	all, failure := op.get("Email", rawArgs(t, object{"properties": []string{"id"}}))
	if failure != "" || len(all["list"].([]object)) != 1 {
		t.Fatalf("get all returned %v %q", all, failure)
	}
	some, failure := op.get("Email", rawArgs(t, object{"ids": []string{id, id, "missing"}, "properties": []string{"id"}}))
	if failure != "" || len(some["list"].([]object)) != 1 || len(some["notFound"].([]string)) != 1 {
		t.Fatalf("get duplicates returned %v %q", some, failure)
	}
	for i := range maxGet {
		id := emailID("folder", 1, imap.UID(i+2))
		op.snapshot.emails[id] = &emailMeta{ID: id}
	}
	if _, failure := op.get("Email", rawArgs(t, object{})); failure != "requestTooLarge" {
		t.Fatal("get all exceeded limit")
	}
}

func TestStandardGetProjectionsAndRequestLimits(t *testing.T) {
	cfg := testConfig(t)
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	op := operation{g: g, snapshotFailure: "serverUnavailable"}
	for _, test := range []struct {
		kind string
		args object
	}{
		{"Mailbox", object{"properties": []string{"totalMessages"}}},
		{"Mailbox", object{"Properties": []string{"name"}}},
		{"Mailbox", object{"fetchTextBodyValues": true}},
		{"Thread", object{"properties": []string{"name"}}},
		{"EmailSubmission", object{"properties": []string{"size"}}},
		{"Identity", object{"properties": []string{"htmlsignature"}}},
		{"Email", object{"ids": []string{}, "properties": []string{"BodyStructure"}}},
		{"Email", object{"bodyProperties": []string{"garbage"}}},
		{"Email", object{"bodyProperties": nil}},
		{"Email", object{"maxBodyValueBytes": int64(maxJMAPInt + 1)}},
		{"Email", object{"ids": []any{nil}}},
		{"Email", object{"ids": []string{"#"}}},
	} {
		if _, failure := op.get(test.kind, rawArgs(t, test.args)); failure != "invalidArguments" {
			t.Fatalf("%s/get %v returned %q", test.kind, test.args, failure)
		}
	}

	op.snapshotFailure = ""
	op.snapshot = &snapshot{}
	op.created = map[string]string{"ref": "mailbox-0"}
	for i := range maxGet + 1 {
		folderID := fmt.Sprintf("mailbox-%d", i)
		op.snapshot.boxes = append(op.snapshot.boxes, &box{ID: folderID, Path: folderID})
		id := fmt.Sprintf("submission-%d", i)
		g.ledger.records[id] = submissionRecord{ID: id, Status: "accepted"}
	}
	for _, kind := range []string{"Mailbox", "EmailSubmission"} {
		if _, failure := op.get(kind, rawArgs(t, object{"ids": nil})); failure != "requestTooLarge" {
			t.Fatalf("%s/get with too many implicit IDs returned %q", kind, failure)
		}
	}
	// The always-present ID is returned even for an empty property projection.
	args := object{"ids": []string{"#ref", "mailbox-0", "#unknown", "#unknown", "#elsewhere", "absent", "absent"},
		"properties": []string{}}
	found, failure := op.get("Mailbox", rawArgs(t, args))
	if failure != "" || !reflect.DeepEqual(found["list"], []object{{"id": "mailbox-0"}}) ||
		!reflect.DeepEqual(found["notFound"], []string{"#unknown", "#elsewhere", "absent"}) {
		t.Fatalf("Get returned %v, %q", found, failure)
	}
}

func TestCreateDraftQuotaAndEpoch(t *testing.T) {
	cert, ca := testTLS(t)
	g := testGatewayForIMAP(t, cert, ca, "", imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapUIDPlus: {}})
	client, closeClient, err := g.connectIMAP(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer closeClient()
	folder := &box{ID: "folder", Path: "Drafts", Role: "drafts"}
	op := operation{g: g, client: client, snapshot: &snapshot{
		boxes:  []*box{folder},
		emails: make(map[string]*emailMeta),
	}}
	input := json.RawMessage(`{"mailboxIds":{"folder":true},"from":[{"email":"sender@example.test"}],
		"to":[{"email":"to@example.test"}],"keywords":{"$seen":true},
		"textBody":[{"partId":"1","type":"text/plain"}],"bodyValues":{"1":{"value":"fixture"}}}`)
	if _, failure := op.createDraft(json.RawMessage(`{"mailboxIds":{"unknown":true}}`)); failure["type"] != "invalidProperties" {
		t.Fatal("draft accepted with an unknown folder")
	}
	for _, test := range []struct{ raw, kind string }{
		{`{"mailboxIds":{"#missing":true}}`, "invalidProperties"},
		{`{"mailboxIds":{"folder":false}}`, "invalidProperties"},
		{`{"mailboxIds":{"folder":true,"other":true}}`, "tooManyMailboxes"},
		{`{"mailboxIds":{"folder":true},"keywords":{"$seen":false}}`, "invalidProperties"},
		{`{"mailboxIds":{"folder":true},"keywords":{"un safe":true}}`, "invalidProperties"},
	} {
		if _, failure := op.createDraft(json.RawMessage(test.raw)); failure["type"] != test.kind {
			t.Fatalf("draft %s returned %v, want %s", test.raw, failure, test.kind)
		}
	}
	if _, failure := op.createDraft(input); failure["type"] != "forbidden" {
		t.Fatal("draft accepted in a read-only folder")
	}
	folder.Writable = true
	for i := range maxMessages {
		op.snapshot.emails[emailID("folder", 1, imap.UID(i+1))] = &emailMeta{}
	}
	if _, failure := op.createDraft(input); failure["type"] != "overQuota" {
		t.Fatal("draft accepted above message limit")
	}
	stale := emailID("folder", 99, 1)
	op.snapshot.emails = map[string]*emailMeta{stale: {ID: stale, MailboxID: folder.ID, Validity: 99}}
	newID, failure := op.createDraft(input)
	if failure != nil || op.snapshot.emails[stale] != nil || op.snapshot.emails[newID] == nil || folder.Unread != 0 {
		t.Fatalf("epoch mismatch left incorrect draft state: %q, %v", newID, failure)
	}
	if result := op.updateEmail(newID, json.RawMessage(`{"keywords/$seen":null}`)); result != nil {
		t.Fatalf("update seen: %s", result)
	}
	if result := op.updateEmail(newID, json.RawMessage(`{"keywords/$seen":false}`)); result["type"] != "invalidPatch" {
		t.Fatalf("invalid update seen: %s", result)
	}
	op.snapshot.emails[newID].Validity++
	if failure := op.updateEmail(newID, json.RawMessage(`{"keywords/$seen":true}`)); failure["type"] != "notFound" {
		t.Fatalf("stale UID update returned %q", failure)
	}
	op.rawBytes = 12 * maxRaw
	if _, failure := op.readRaw(&emailMeta{Size: 1}); failure != "requestTooLarge" {
		t.Fatal("reading after exhausting request budget succeeded")
	}
}

func TestIncompleteDraftFromCustomMailbox(t *testing.T) {
	cert, ca := testTLS(t)
	g := testGatewayForIMAP(t, cert, ca, "", imap.CapSet{
		imap.CapIMAP4rev1: {}, imap.CapUIDPlus: {},
	})
	account := g.config.AccountID
	const token = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	calls := gatewayCalls(t, g, token,
		[3]any{"Mailbox/set", object{"accountId": account, "create": object{"work": object{"name": "Work"}}}, "folder"},
		[3]any{"Email/set", object{"accountId": account, "create": object{
			"incomplete": object{"mailboxIds": object{"#work": true}, "keywords": object{"$Draft": true, "$Flagged": true, "Custom": true}, "subject": "Working"},
			"address": object{"mailboxIds": object{"#work": true},
				"from": []object{{"email": g.config.IdentityEmail}}, "header:To": " unfinished@"},
			"default": object{"mailboxIds": object{"#work": true}},
		}}, "create"},
		[3]any{"EmailSubmission/set", object{"accountId": account, "create": object{
			"missingFrom": object{"emailId": "#incomplete", "identityId": identityID},
			"invalidTo":   object{"emailId": "#address", "identityId": identityID},
		}}, "submit"},
		[3]any{"Email/get", object{"accountId": account, "ids": []string{"#incomplete", "#default"},
			"fetchTextBodyValues": true, "properties": []string{"mailboxIds", "keywords", "from", "to", "messageId", "sentAt", "bodyValues"}}, "read"},
	)
	failures, _ := calls[2].Args["notCreated"].(map[string]any)
	for name, property := range map[string]string{"missingFrom": "from", "invalidTo": "to"} {
		failure, _ := failures[name].(map[string]any)
		properties, _ := failure["properties"].([]any)
		if failure["type"] != "invalidEmail" || len(properties) != 1 || properties[0] != property {
			t.Fatalf("unfinished draft submission %q returned %v", name, calls[2])
		}
	}
	list, _ := calls[3].Args["list"].([]any)
	if len(list) != 2 {
		t.Fatalf("drafts unavailable: %v", calls[3])
	}
	record := list[0].(map[string]any)
	flags := record["keywords"].(map[string]any)
	body := record["bodyValues"].(map[string]any)["1"].(map[string]any)
	if record["from"] != nil || record["to"] != nil || record["messageId"] == nil || record["sentAt"] == nil ||
		body["value"] != "" || len(flags) != 3 || flags["$draft"] != true || flags["$flagged"] != true || flags["custom"] != true {
		t.Fatalf("unexpected unfinished draft projection: %v", record)
	}
	if flags := list[1].(map[string]any)["keywords"].(map[string]any); len(flags) != 0 {
		t.Fatalf("omitted keywords defaulted to %v", flags)
	}
}

func TestSubmissionInputAndExistingReservations(t *testing.T) {
	cert, ca := testTLS(t)
	g := testGatewayForIMAP(t, cert, ca, "", imap.CapSet{imap.CapIMAP4rev1: {}})
	client, closeClient, err := g.connectIMAP(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer closeClient()
	id := emailID("drafts", 2, 1)
	op := operation{g: g, ctx: context.Background(), client: client, snapshotFailure: "serverUnavailable"}
	submit := func(email, identity string) (string, object) {
		t.Helper()
		raw, err := json.Marshal(object{"emailId": email, "identityId": identity})
		if err != nil {
			t.Fatal(err)
		}
		return op.submit(raw)
	}
	fail := func(kind, email, identity string) {
		t.Helper()
		if id, failure := submit(email, identity); id != "" || failure["type"] != kind {
			t.Fatalf("submission %q returned ID %q, error %v, want %q", email, id, failure, kind)
		}
	}
	fail("invalidProperties", id, "foreign")
	fail("invalidProperties", "unknown", identityID)
	g.ledger.failed = true
	fail("serverFail", id, identityID)
	g.ledger.failed = false
	fail("serverUnavailable", id, identityID)
	email := &emailMeta{ID: id, Path: "Drafts", MailboxID: "drafts", Validity: 2, UID: 1, Keywords: map[string]bool{}}
	op.snapshotFailure = ""
	op.snapshot = &snapshot{emails: map[string]*emailMeta{}}
	fail("invalidProperties", id, identityID)
	op.snapshot = &snapshot{emails: map[string]*emailMeta{id: email}}
	fail("invalidProperties", id, identityID)
	email.Size = maxRaw + 1
	fail("tooLarge", id, identityID)
	email.Size = 1
	op.rawBytes = 12 * maxRaw
	fail("requestTooLarge", id, identityID)
}

func TestSubmissionResolvesMessageIDDurably(t *testing.T) {
	cert, ca := testTLS(t)
	c := testConfig(t)
	c.IMAP.CAFile = ca
	c.DraftsMailbox = "Drafts"
	addr, user := serveTestIMAP(t, c.IMAP, cert, imap.CapSet{imap.CapIMAP4rev1: {}}, nil)
	c.IMAP.Address = addr
	g, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	const key = "0123456789abcdef0123456789abcdef"
	base := "From: sender@example.test\r\nTo: to@example.test\r\nMessage-ID: <" + key + "@jmap.invalid>\r\nContent-Type: text/plain\r\n"
	appendFixture := func(raw string) string {
		t.Helper()
		data, err := user.Append("Drafts", strings.NewReader(raw), &imap.AppendOptions{Time: time.Now(), Flags: []imap.Flag{imap.FlagDraft}})
		if err != nil {
			t.Fatal(err)
		}
		return emailID(mailboxID(c.AccountID, "Drafts"), data.UIDValidity, data.UID)
	}
	id := appendFixture(base + "\r\nfixture\r\n")
	invalid := appendFixture(base + "Cc: recipient-without-domain\r\n\r\nfixture\r\n")
	op := operation{g: g, ctx: context.Background()}
	defer func() {
		if op.closeIMAP != nil {
			op.closeIMAP()
		}
	}()
	send := func(id string) (string, object) {
		raw, err := json.Marshal(object{"emailId": id, "identityId": identityID})
		if err != nil {
			t.Fatal(err)
		}
		return op.submit(raw)
	}
	if _, failure := send(invalid); failure["type"] != "invalidEmail" {
		t.Fatalf("invalid envelope produced %v", failure)
	}
	entry := submissionRecord{ID: "original", EmailID: emailID("old", 1, 1), IdentityID: identityID, Status: "accepted"}
	g.ledger.records[key] = entry
	if got, failure := send(id); got != entry.ID || failure != nil {
		t.Fatalf("moved draft returned %q %v", got, failure)
	}
	entry.Status = "pending"
	g.ledger.records[key] = entry
	if got, failure := send(id); got != "" || failure["type"] != "serverFail" {
		t.Fatalf("uncertain moved draft returned %q %v", got, failure)
	}
}

func TestSubmissionLedgerWriteFailures(t *testing.T) {
	cert, ca := testTLS(t)
	for _, test := range []struct {
		name, smtpFault, diagnostic string
		failedWrite                 int
	}{
		{"reserve", "", "Submission could not be reserved", 1},
		{"release rejected", "rcpt", "Submission ledger requires operator recovery", 2},
		{"record accepted", "", "SMTP accepted the message. Submission ledger requires operator recovery", 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := testConfig(t)
			c.IMAP.CAFile = ca
			c.DraftsMailbox = "Drafts"
			address, user := serveTestIMAP(t, c.IMAP, cert, imap.CapSet{imap.CapIMAP4rev1: {}}, nil)
			c.IMAP.Address = address
			var smtp *smtpFixture
			if test.failedWrite > 1 {
				c.SMTP.CAFile = ca
				c.SMTP.Address, smtp = serveTestSMTP(t, c.SMTP, cert, test.smtpFault)
			}
			g, err := New(c)
			if err != nil {
				t.Fatal(err)
			}
			defer g.Close()
			renames := 0
			g.ledger.files.rename = func(source, destination string) error {
				renames++
				if renames == test.failedWrite {
					return diskError
				}
				return localAtomicFiles.rename(source, destination)
			}
			const key = "0123456789abcdef0123456789abcdef"
			raw := "From: sender@example.test\r\nTo: to@example.test\r\nMessage-ID: <" + key + "@jmap.invalid>\r\nContent-Type: text/plain\r\n\r\nHello over IMAP and SMTP\r\n"
			added, err := user.Append("Drafts", strings.NewReader(raw), &imap.AppendOptions{Time: time.Now(), Flags: []imap.Flag{imap.FlagDraft}})
			if err != nil {
				t.Fatal(err)
			}
			id := emailID(mailboxID(c.AccountID, "Drafts"), added.UIDValidity, added.UID)
			submission := object{"accountId": c.AccountID, "create": object{
				"attempt": object{"emailId": id, "identityId": identityID},
			}}
			result := gatewayCalls(t, g, c.Token, [3]any{"EmailSubmission/set", submission, "attempt"})[0]
			rejection := result.Args["notCreated"].(map[string]any)["attempt"].(map[string]any)
			if rejection["type"] != "serverFail" || rejection["description"] != test.diagnostic || renames != test.failedWrite {
				t.Fatalf("unexpected submission result %v after %d ledger writes", rejection, renames)
			}
			durable, err := os.ReadFile(filepath.Join(c.StateDir, "submissions.json"))
			if err != nil {
				t.Fatal(err)
			}
			var state struct{ Records map[string]submissionRecord }
			if err := json.Unmarshal(durable, &state); err != nil {
				t.Fatal(err)
			}
			prepared, failure := prepareSubmission([]byte(raw), c.IdentityEmail, nil)
			if failure != nil {
				t.Fatal(failure)
			}
			if test.failedWrite == 1 && len(state.Records) != 0 || test.failedWrite == 2 && state.Records[prepared.key].Status != "pending" {
				t.Fatal("unexpected durable state after write failure")
			}
			if smtp != nil {
				select {
				case err := <-smtp.done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("SMTP fixture did not finish")
				}
				if test.smtpFault == "" && extractTestMessageKey(t, smtp, "") != key {
					t.Fatal("wrong message sent before acceptance write failure")
				}
			}
		})
	}
}
