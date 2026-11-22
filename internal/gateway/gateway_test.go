package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
)

func testConfig(t *testing.T) Config {
	t.Helper()
	stateDir := t.TempDir()
	if err := os.Chmod(stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	credentials := Upstream{Address: "localhost:1", Mode: "tls", Username: "sender", Password: "fixture"}
	return Config{
		Listen: "localhost:8443", PublicOrigin: "https://gateway.example", TLSCert: "cert", TLSKey: "key",
		StateDir: stateDir, AccountID: "sender", Token: strings.Repeat("x", 40),
		IdentityEmail: "sender@example.test", IMAP: credentials, SMTP: credentials,
	}
}

func TestSessionAndBatchedRequests(t *testing.T) {
	c := testConfig(t)
	g, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	send := func(method, path, body, token string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, "https://internal.example"+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r)
		return w
	}
	if status := send(http.MethodGet, "/.well-known/jmap", "", "").Code; status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated session HTTP %d", status)
	}
	session := send(http.MethodGet, "/.well-known/jmap", "", c.Token)
	var sessionData object
	if session.Code != http.StatusOK || json.Unmarshal(session.Body.Bytes(), &sessionData) != nil ||
		sessionData["apiUrl"] != "https://gateway.example/jmap" || strings.Contains(session.Body.String(), c.Token) {
		t.Fatal("discovery must use the configured origin and omit the token")
	}
	capabilities := sessionData["capabilities"].(map[string]any)[core].(map[string]any)
	if capabilities["maxConcurrentRequests"] != float64(maxConcurrent) || capabilities["maxConcurrentRequest"] != nil {
		t.Fatal("discovery must use the capability name corrected by RFC 8620 erratum 5791")
	}

	api := send(http.MethodPost, "/jmap", `{
		"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:submission"],
		"methodCalls":[
			["Identity/get",{"accountId":"wrong"},"wrong"],
			["Identity/get",{"accountId":"sender"},"list"],
			["Core/echo",{"#ids":{"resultOf":"list","name":"Identity/get","path":"/list/*/id"}},"ref"],
			["Identity/get",{"accountId":"sender","#ids":{"resultOf":"list","name":"Identity/get","path":"/missing"}},"bad"]
		]
	}`, c.Token)
	var methodData struct {
		Responses [][3]json.RawMessage `json:"methodResponses"`
	}
	if api.Code != http.StatusOK || json.Unmarshal(api.Body.Bytes(), &methodData) != nil || len(methodData.Responses) != 4 {
		t.Fatal("expected four successful HTTP-level responses")
	}
	want := []string{`{"type":"accountNotFound"}`, "", `{"ids":["sender"]}`, `{"type":"invalidResultReference"}`}
	for index, args := range methodData.Responses {
		if want[index] != "" && string(args[1]) != want[index] {
			t.Errorf("response %d = %s, want %s", index, args[1], want[index])
		}
	}
}

func TestMailIDsScopeUIDAndEpoch(t *testing.T) {
	inbox := mailboxID("account", "INBOX")
	drafts := mailboxID("account", "Drafts")
	if mailboxID("account", "inbox") != inbox || mailboxID("other", "INBOX") == inbox {
		t.Fatal("Inbox identity lost case folding or account isolation")
	}
	id := emailID(inbox, 12, 1)
	if id == emailID(drafts, 12, 1) || id == emailID(inbox, 13, 1) || id == emailID(inbox, 12, 2) {
		t.Fatal("message identity lost mailbox, UIDVALIDITY, or UID scope")
	}
	flags := keywords([]imap.Flag{imap.FlagSeen, imap.FlagDraft, imap.FlagDeleted, "$SEEN", "Custom"})
	snapshot := snapshot{emails: map[string]*emailMeta{id: {ID: id, Keywords: flags}}}
	if !flags["$seen"] || !flags["$draft"] || !flags["custom"] || len(flags) != 3 {
		t.Fatalf("unexpected mapped flags %v", flags)
	}
	oldState := snapshot.state("Email")
	delete(flags, "$seen")
	if snapshot.state("Email") == oldState {
		t.Fatal("seen-state change must change Email state")
	}
}

func TestDraftMIMERoundTrip(t *testing.T) {
	const identity = "sender@example.test"
	input := json.RawMessage(`{
		"mailboxIds":{"drafts":true},
		"from":[{"email":"sender@example.test","name":"Lähettäjä"}],
		"to":[{"email":"recipient@example.test"}],
		"subject":"Terve",
		"textBody":[{"partId":"1","type":"text/plain"}],
		"bodyValues":{"1":{"value":"héllo\n.second"}}
	}`)
	draft, draftFailure := makeDraft(input, time.Now(), func(value string) bool { return value == identity }, nil)
	raw := draft.raw
	if draftFailure != nil || len(draft.keywords) != 0 {
		t.Fatalf("draft creation failed: %v", draftFailure)
	}
	prepared, envelopeFailure := prepareSubmission(raw, identity, nil)
	if len(prepared.legacyKey) != 32 || len(prepared.recipients) != 1 || prepared.recipients[0] != "recipient@example.test" || envelopeFailure != nil {
		t.Fatalf("submission envelope failed: %v", envelopeFailure)
	}
	meta := emailMeta{ID: emailID("drafts", 1, 1)}
	message, failure := parseMIME(raw, meta.ID)
	if failure != "" {
		t.Fatal(failure)
	}
	record := message.emailRecord(&meta, getArgs{
		Properties: defaultEmailProperties, FetchTextBodyValues: true, MaxBodyValueBytes: 2,
	})
	body := record["bodyValues"].(object)["1"].(object)
	if body["value"] != "h" || body["isTruncated"] != true || body["isEncodingProblem"] != false {
		t.Fatalf("unexpected truncated body: %v", body)
	}
	if value := textValue(message.plain[0].Value); value != "héllo\n.second\n" {
		t.Fatalf("unexpected decoded MIME body: %q", value)
	}
}

func TestSubmissionReplaySurvivesRestart(t *testing.T) {
	c := testConfig(t)
	id, pending := emailID("drafts", 1, 1), emailID("drafts", 1, 2)
	l, err := openLedger(c.StateDir, c.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	l.records = map[string]submissionRecord{
		"original": {ID: "original", EmailID: id, IdentityID: identityID, From: c.IdentityEmail,
			To: "recipient@example.test", SendAt: time.Now(), Status: "accepted"},
		"pending": {ID: "pending", EmailID: pending, IdentityID: identityID, From: c.IdentityEmail,
			To: "recipient@example.test", SendAt: time.Now(), Status: "pending"},
	}
	if err := l.save(); err != nil {
		t.Fatal(err)
	}
	if other, err := openLedger(c.StateDir, c.AccountID); err == nil {
		other.lock.Close()
		t.Fatal("second process could open the active ledger")
	}
	if err := l.lock.Close(); err != nil {
		t.Fatal(err)
	}
	g, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	op := operation{g: g, ctx: context.Background()}
	submit := func(emailID string) (string, object) {
		input, _ := json.Marshal(object{"emailId": emailID, "identityId": identityID})
		return op.submit(input)
	}
	if got, failure := submit(id); got != "original" || failure != nil {
		t.Fatal("accepted replay lost its original submission ID")
	}
	if got, failure := submit(pending); got != "" || failure["type"] != "serverFail" {
		t.Fatal("uncertain replay must stay blocked")
	}
	if op.client != nil || op.snapshotFailure != "" {
		t.Fatal("replay must avoid upstream I/O")
	}
}
