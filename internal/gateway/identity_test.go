package gateway

import (
	"encoding/json"
	"net/mail"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
)

func identityCall(t *testing.T, g *Gateway, cfg Config, name string, data object) object {
	t.Helper()
	data["accountId"] = cfg.AccountID
	return gatewayCalls(t, g, cfg.Token, [3]any{"Identity/" + name, data, "identity"})[0].Args
}

func TestIdentityLifecyclePersists(t *testing.T) {
	cfg := testConfig(t)
	const alias = "orders@example.test"
	cfg.IdentityAliases = []string{alias}
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	before := identityCall(t, g, cfg, "get", object{})
	change := identityCall(t, g, cfg, "set", object{"ifInState": before["state"],
		"create": object{"alias": object{"email": alias, "name": "Operations", "textSignature": "Orders\nTeam",
			"htmlSignature": "<p>Orders</p>", "replyTo": []address{{Email: "help@example.test"}}, "bcc": []address{{Email: "archive@example.test"}}},
			"denied": object{"email": "forged@example.test"}},
		"update": object{identityID: object{"email": cfg.IdentityEmail, "id": identityID, "name": "Default", "mayDelete": false},
			"#alias": object{"name": "Orders"}, "missing": object{}},
		"destroy": []string{identityID, "missing"},
	})
	id := testPushAssignment(t, change, "created", "alias")["id"].(string)
	if change["oldState"] != before["state"] || change["newState"] == before["state"] ||
		testPushAssignment(t, change, "notCreated", "denied")["type"] != "forbiddenFrom" ||
		testPushAssignment(t, change, "notDestroyed", identityID)["type"] != "forbidden" ||
		testPushAssignment(t, change, "notDestroyed", "missing")["type"] != "notFound" ||
		testPushAssignment(t, change, "notUpdated", "missing")["type"] != "notFound" {
		t.Fatalf("unexpected Identity/set response: %v", change)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	g = reopened
	got := identityCall(t, g, cfg, "get", object{"ids": []string{id}})
	entry := got["list"].([]any)[0].(map[string]any)
	if got["state"] != change["newState"] || entry["name"] != "Orders" || entry["email"] != alias ||
		entry["mayDelete"] != true || entry["textSignature"] != "Orders\nTeam" || entry["htmlSignature"] != "<p>Orders</p>" ||
		entry["replyTo"].([]any)[0].(map[string]any)["email"] != "help@example.test" ||
		entry["bcc"].([]any)[0].(map[string]any)["email"] != "archive@example.test" {
		t.Fatalf("identity did not persist: %v", got)
	}
	delta := identityCall(t, g, cfg, "changes", object{"sinceState": before["state"]})
	if !reflect.DeepEqual(delta["created"], []any{id}) || !reflect.DeepEqual(delta["updated"], []any{identityID}) {
		t.Fatalf("incorrect state delta: %v", delta)
	}
	if result := identityCall(t, g, cfg, "set", object{"ifInState": before["state"]}); result["type"] != "stateMismatch" {
		t.Fatalf("stale state accepted: %v", result)
	}
	update := identityCall(t, g, cfg, "set", object{"update": object{id: object{"replyTo": nil, "bcc": nil}}})
	if update["updated"] == nil || update["newState"] == change["newState"] {
		t.Fatalf("null did not clear address defaults: %v", update)
	}
	removed := identityCall(t, g, cfg, "set", object{"destroy": []string{id}})
	if !reflect.DeepEqual(removed["destroyed"], []any{id}) {
		t.Fatalf("identity wasn't destroyed: %v", removed)
	}
	aliasAgain := identityCall(t, g, cfg, "set", object{"create": object{"second": object{"email": alias}}})
	removedByConfig := testPushAssignment(t, aliasAgain, "created", "second")["id"]
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	cfg.IdentityAliases = nil
	reopened, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	g = reopened
	delta = identityCall(t, g, cfg, "changes", object{"sinceState": aliasAgain["newState"]})
	if !reflect.DeepEqual(delta["destroyed"], []any{removedByConfig}) {
		t.Fatalf("revoked alias was not removed: %v", delta)
	}
}

func TestIdentityAliasSMTP(t *testing.T) {
	cfg := testConfig(t)
	const alias = "alias@example.test"
	cfg.IdentityAliases = []string{alias}
	cert, ca := testTLS(t)
	cfg.IMAP.Address, _ = serveTestIMAP(t, cfg.IMAP, cert, imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapUIDPlus: {}}, nil)
	cfg.IMAP.CAFile, cfg.SMTP.CAFile = ca, ca
	smtpAddress, fixture := serveTestSMTP(t, cfg.SMTP, cert, "")
	cfg.SMTP.Address, cfg.DraftsMailbox = smtpAddress, "Drafts"
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	draft := draftFixture(mailboxID(cfg.AccountID, "Drafts"), alias)
	draft["replyTo"] = []address{{Email: "support@example.test"}}
	draft["textBody"] = []object{{"partId": "plain", "type": "text/plain"}}
	draft["bodyValues"] = object{"plain": object{"value": "Identity alias delivery"}}
	submit := func(identity, id string) object {
		return object{"accountId": cfg.AccountID, "create": object{"send": object{"emailId": id, "identityId": identity}}}
	}
	flow := gatewayCalls(t, g, cfg.Token,
		[3]any{"Identity/set", object{"accountId": cfg.AccountID, "create": object{"alias": object{"email": alias}}}, "identity"},
		[3]any{"Email/set", object{"accountId": cfg.AccountID, "create": object{"draft": draft}}, "draft"},
		[3]any{"EmailSubmission/set", submit(identityID, "#draft"), "wrong"},
		[3]any{"EmailSubmission/set", submit("#alias", "#draft"), "right"})
	if failure := testPushAssignment(t, flow[2].Args, "notCreated", "send"); failure["type"] != "forbiddenFrom" {
		t.Fatalf("primary identity sent the alias message: %v", flow)
	}
	submissionID := testPushAssignment(t, flow[3].Args, "created", "send")["id"]
	profileID := testPushAssignment(t, flow[0].Args, "created", "alias")["id"]
	emailID := testPushAssignment(t, flow[1].Args, "created", "draft")["id"].(string)
	select {
	case raw := <-fixture.received:
		message, err := mail.ReadMessage(strings.NewReader(raw))
		if err != nil || message.Header.Get("From") != "<alias@example.test>" || message.Header.Get("Reply-To") != "<support@example.test>" {
			t.Fatalf("wrong SMTP headers: %s %v", raw, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("did not receive alias SMTP submission")
	}
	if err := <-fixture.done; err != nil {
		t.Fatal(err)
	}
	got := gatewayCalls(t, g, cfg.Token,
		[3]any{"EmailSubmission/get", object{"accountId": cfg.AccountID, "ids": []any{submissionID}}, "get"},
		[3]any{"EmailSubmission/set", submit(identityID, emailID), "replay"})
	record := got[0].Args["list"].([]any)[0].(map[string]any)
	if record["identityId"] != profileID ||
		record["envelope"].(map[string]any)["mailFrom"].(map[string]any)["email"] != alias ||
		testPushAssignment(t, got[1].Args, "notCreated", "send")["type"] != "invalidProperties" {
		t.Fatalf("submission did not preserve selected identity: %v", got)
	}
}

func TestIdentityInputAndStorageErrors(t *testing.T) {
	cfg := testConfig(t)
	for _, aliases := range [][]string{make([]string, maxIdentities), {cfg.IdentityEmail}, {"*@example.test"}, {"no-domain"}} {
		rejected := cfg
		rejected.IdentityAliases = aliases
		if _, err := New(rejected); err == nil {
			t.Fatalf("accepted invalid configured aliases: %v", aliases)
		}
	}
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, code string
		args         object
	}{
		{"get", "invalidArguments", object{"properties": []string{"unknown"}}},
		{"get", "invalidArguments", object{"fetchTextBodyValues": true}},
		{"set", "invalidArguments", object{"unknown": true}},
		{"set", "requestTooLarge", object{"destroy": make([]string, maxSet+1)}},
		{"set", "invalidArguments", object{"create": object{"#bad": object{}}}},
	} {
		if response := identityCall(t, g, cfg, tc.method, tc.args); response["type"] != tc.code {
			t.Fatalf("got %v, want %s", response, tc.code)
		}
	}
	data, err := json.Marshal(object{"email": "not-mail", "name": "line\nbreak", "bcc": make([]address, maxSubmissionRecipients+1),
		"replyTo": []address{{Email: "wrong"}}, "mayDelete": nil, "textSignature": strings.Repeat("a", maxSignatureBytes+1), "id": "notvalid"})
	if err != nil {
		t.Fatal(err)
	}
	if _, failed := editIdentity("", identityProfile{}, data); len(failed["properties"].([]string)) != 7 {
		t.Fatalf("invalid fields: %v", failed)
	}
	for _, raw := range []string{"{}", "null", "{\"email\":null}", "{\"email\":true}"} {
		if _, failed := editIdentity("", identityProfile{}, json.RawMessage(raw)); failed["type"] != "invalidProperties" {
			t.Fatalf("bad creation property %q: %v", raw, failed)
		}
	}
	if _, failed := editIdentity(identityID, identityProfile{}, json.RawMessage("null")); failed["type"] != "invalidPatch" {
		t.Fatalf("bad update: %v", failed)
	}
	badUpdate := identityCall(t, g, cfg, "set", object{"update": object{identityID: object{"email": "other@example.test"}}})
	if testPushAssignment(t, badUpdate, "notUpdated", identityID)["type"] != "invalidProperties" {
		t.Fatalf("updated an immutable sender: %v", badUpdate)
	}
	badSubmission := gatewayCalls(t, g, cfg.Token, [3]any{"EmailSubmission/set", object{
		"accountId": cfg.AccountID, "create": object{"invalid": object{"identityId": true}},
	}, "bad"})[0]
	if testPushAssignment(t, badSubmission.Args, "notCreated", "invalid")["type"] != "invalidProperties" {
		t.Fatalf("accepted invalid submission arguments: %v", badSubmission)
	}
	for i := range maxIdentities - 1 {
		g.identities[string(rune('a'+i))] = identityProfile{Email: cfg.IdentityEmail}
	}
	validCreate := object{"create": object{"candidate": object{"email": cfg.IdentityEmail}}}
	if result := identityCall(t, g, cfg, "set", validCreate); testPushAssignment(t, result, "notCreated", "candidate")["type"] != "overQuota" {
		t.Fatalf("identity quota bypassed: %v", result)
	}
	clear(g.identities)
	g.ledger.files.rename = func(string, string) error { return diskError }
	if result := identityCall(t, g, cfg, "set", validCreate); result["type"] != "serverFail" || len(g.identities) != 0 {
		t.Fatalf("failed identity write became visible: %v", result)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(cfg.StateDir, identityFile)
	if err := os.Symlink(identityFile, file); err != nil {
		t.Fatal(err)
	}
	if _, err := New(cfg); err == nil || err.Error() != "cannot open identity state" {
		t.Fatalf("unreadable state: %v", err)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	for raw, want := range map[string]string{"invalid": "invalid identity state", "{\"bad\":{\"Email\":\"bad\"}}": "invalid identity profile"} {
		if err := os.WriteFile(file, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := New(cfg); err == nil || err.Error() != want {
			t.Fatalf("corrupt state: %v", err)
		}
	}
}
