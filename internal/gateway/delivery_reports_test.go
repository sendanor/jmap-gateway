package gateway

import (
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
)

const reportRecipient = "to+dsn@example.test"

func reportFixture(envid, recipients string) string {
	return "From: relay@example.test\r\nSubject: Delivery report\r\n" +
		"MIME-Version: 1.0\r\nContent-Type: multipart/report; report-type=delivery-status; boundary=test\r\n\r\n" +
		"--test\r\nContent-Type: text/plain\r\n\r\nStatus report\r\n" +
		"--test\r\nContent-Type: message/delivery-status\r\n\r\n" +
		"Original-Envelope-Id: " + envid + "\r\nReporting-MTA: dns; relay.example.test\r\n\r\n" +
		recipients + "\r\n--test--\r\n"
}

func TestDeliveryReportParsing(t *testing.T) {
	recipients := "Original-Recipient: rfc822; " + reportRecipient + "\r\n" +
		"Final-Recipient: rfc822; forwarded@example.test\r\nAction: delivered\r\nStatus: 2.0.0\r\n" +
		"Diagnostic-Code: smtp; 250 2.0.0 Delivered\r\n\r\n" +
		"Final-Recipient: rfc822; second@example.test\r\nAction: failed\r\nStatus: 5.1.1\r\n" +
		"Diagnostic-Code: smtp; 550 5.1.1 Missing\r\n\r\n" +
		"Final-Recipient: rfc822; third@example.test\r\nAction: delayed\r\nStatus: 4.1.1\r\n\r\n" +
		"Final-Recipient: rfc822; mismatch@example.test\r\nAction: delivered\r\nStatus: 5.1.1\r\n\r\n" +
		"Final-Recipient: rfc822; bad@example.test\r\nAction: failed\r\nStatus: invalid\r\n"
	raw := reportFixture("track", recipients)
	envid, outcomes := parseDeliveryReport([]byte(raw))
	if envid != "track" || !reflect.DeepEqual(outcomes, map[string]reportOutcome{
		reportRecipient:       {"yes", "250 2.0.0 Delivered"},
		"second@example.test": {"no", "550 5.1.1 Missing"},
		"third@example.test":  {},
	}) {
		t.Fatalf("unexpected report result: %s %v", envid, outcomes)
	}
	for _, tc := range []struct{ name, raw string }{
		{"bad message", "not a message"},
		{"wrong MIME", strings.Replace(raw, "multipart/report", "multipart/mixed", 1)},
		{"no delivery part", strings.Replace(raw, "message/delivery-status", "text/plain", 1)},
		{"truncated", strings.TrimSuffix(raw, "\r\n--test--\r\n")},
		{"no ENVID", reportFixture("", recipients)},
		{"malformed recipient block", reportFixture("track", "invalid field\r\n")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if key, outcomes := parseDeliveryReport([]byte(tc.raw)); key != "" || outcomes != nil {
				t.Fatalf("parsed invalid report: %s %v", key, outcomes)
			}
		})
	}
}

type reportFolderSession struct {
	imapserver.Session
	readOnly *atomic.Bool
}

func (s reportFolderSession) Select(name string, options *imap.SelectOptions) (*imap.SelectData, error) {
	selected, err := s.Session.Select(name, options)
	if err == nil && name == "Plain" && s.readOnly.Load() {
		selected.ReadOnly = true
	}
	return selected, err
}

type reportLiteral struct{ *strings.Reader }

func (r reportLiteral) Size() int64 { return r.Reader.Size() }

func TestDeliveryReportCorrelation(t *testing.T) {
	cfg := testConfig(t)
	cfg.SMTPDeliveryNotifications, cfg.SMTPDeliveryReportMailbox = true, "Plain"
	cert, ca := testTLS(t)
	var readOnly atomic.Bool
	address, user := serveTestIMAP(t, cfg.IMAP, cert, imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapUIDPlus: {}},
		func(s imapserver.Session) imapserver.Session { return reportFolderSession{s, &readOnly} })
	cfg.IMAP.Address, cfg.IMAP.CAFile, cfg.SMTP.CAFile = address, ca, ca
	address, relay := serveTestSMTP(t, cfg.SMTP, cert, "dsn")
	cfg.SMTP.Address = address
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	call := func(method string, args object) object {
		t.Helper()
		args["accountId"] = cfg.AccountID
		result := gatewayCalls(t, g, cfg.Token, [3]any{method, args, "report"})[0]
		if result.Name != method {
			t.Fatalf("%s returned %v", method, result)
		}
		return result.Args
	}
	draft := draftFixture(mailboxID(cfg.AccountID, "Drafts"), cfg.IdentityEmail)
	email := call("Email/set", object{"create": object{"draft": draft}})["created"].(map[string]any)["draft"].(map[string]any)["id"]
	envid := "client-id"
	envelope := testEnvelope(cfg.IdentityEmail, reportRecipient)
	envelope.From.Parameters = map[string]*string{"ENVID": &envid}
	submit := func() object {
		return call("EmailSubmission/set", object{"create": object{
			"send": object{"emailId": email, "identityId": identityID, "envelope": envelope},
		}})["created"].(map[string]any)["send"].(map[string]any)
	}
	submission := submit()["id"]
	if err := <-relay.done; err != nil {
		t.Fatal(err)
	}
	prefix := "FROM:<" + cfg.IdentityEmail + "> ENVID="
	key, ok := strings.CutPrefix(<-relay.mailFrom, prefix)
	if !ok || !strings.HasPrefix(key, "jmap-") {
		t.Fatalf("missing gateway report key: %q", key)
	}
	if submit()["id"] != submission {
		t.Fatal("replay with original envelope created a new submission")
	}
	envid = key
	if submit()["id"] != submission {
		t.Fatal("replay with effective envelope created a new submission")
	}
	get := func() (any, map[string]any) {
		t.Helper()
		result := call("EmailSubmission/get", object{"ids": []any{submission}})
		return result["state"], result["list"].([]any)[0].(map[string]any)
	}
	initial, _ := get()
	newReport := func(recipient, action, status, diagnostic string) string {
		return "Final-Recipient: rfc822; " + recipient + "\r\nAction: " + action + "\r\nStatus: " + status +
			"\r\n" + diagnostic
	}
	now := time.Now().UTC()
	appendReport := func(path, content string, received time.Time) {
		t.Helper()
		if _, err := user.Append(path, reportLiteral{strings.NewReader(content)}, &imap.AppendOptions{Time: received}); err != nil {
			t.Fatal(err)
		}
	}
	appendReport("INBOX", reportFixture(key, newReport(reportRecipient, "delivered", "2.0.0", "")), now)
	appendReport("Plain", reportFixture("wrong", newReport(reportRecipient, "delivered", "2.0.0", "")), now)
	appendReport("Plain", reportFixture(key, newReport("other@example.test", "delivered", "2.0.0", "")), now)
	appendReport("Plain", reportFixture(key, newReport(reportRecipient, "delayed", "4.0.0", "")), now)
	failed := reportFixture(key, newReport(reportRecipient, "failed", "5.1.1", "Diagnostic-Code: smtp; 550 5.1.1 Missing\r\n"))
	appendReport("Plain", failed, now.Add(time.Minute))
	appendReport("Plain", reportFixture(key, newReport(reportRecipient, "delivered", "2.0.0", "")), now.Add(2*time.Minute))
	if state, row := get(); state != initial || len(row["dsnBlobIds"].([]any)) != 0 {
		t.Fatalf("writable IMAP folder affected delivery status: %v", row)
	}
	readOnly.Store(true)

	// A failed ledger write must not publish a state the next process cannot read.
	g.ledger.files.rename = func(string, string) error { return os.ErrPermission }
	if state, row := get(); state != initial || len(row["dsnBlobIds"].([]any)) != 0 {
		t.Fatalf("an uncommitted report affected delivery status: %v", row)
	}
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
	reopen()
	changes := call("EmailSubmission/changes", object{"sinceState": initial})
	if !reflect.DeepEqual(changes["updated"], []any{submission}) {
		t.Fatalf("missing submission change: %v", changes)
	}
	state, row := get()
	got := row["deliveryStatus"].(map[string]any)[reportRecipient]
	want := map[string]any{"delivered": "no", "displayed": "unknown", "smtpReply": "550 5.1.1 Missing"}
	ids := row["dsnBlobIds"].([]any)
	if !reflect.DeepEqual(got, want) || len(ids) != 3 {
		t.Fatalf("unexpected delivery result: %v %v", got, ids)
	}
	response := gatewayRequest(g, "GET", "/download/"+cfg.AccountID+"/"+ids[1].(string)+"/report.eml", cfg.Token, nil)
	if response.Code != 200 || response.Body.String() != failed {
		t.Fatalf("delivery report download returned %d", response.Code)
	}
	reopen()
	after, saved := get()
	if after != state || !reflect.DeepEqual(saved, row) {
		t.Fatal("report outcome changed on restart")
	}
}

func TestDeliveryReportMissingSourceOrBudget(t *testing.T) {
	g := &Gateway{
		config: Config{SMTPDeliveryReportMailbox: "reports"},
		ledger: &ledger{records: map[string]submissionRecord{"key": {Status: "accepted", ReportKey: "track"}}},
	}
	for _, op := range []*operation{
		{g: g, snapshotFailure: "serverUnavailable"},
		{g: g, snapshot: &snapshot{}},
		{g: g, snapshot: &snapshot{boxes: []*box{{Path: "reports", ACL: &mailboxACL{}}}}},
		{g: g, rawBytes: 12 * maxRaw, snapshot: &snapshot{
			boxes:  []*box{{Path: "reports", ID: "box"}},
			emails: map[string]*emailMeta{"e-a": {ID: "e-a", MailboxID: "box", Size: 1}},
		}},
	} {
		op.refreshDeliveryReports()
		if len(g.ledger.records["key"].DeliveryReports) != 0 {
			t.Fatal("recorded an unavailable delivery report")
		}
	}
}
