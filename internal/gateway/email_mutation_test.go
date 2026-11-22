package gateway

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
)

func TestEmailSetKeywordsAndTargetedDestroy(t *testing.T) {
	config := testConfig(t)
	cert, ca := testTLS(t)
	address, user := serveTestIMAP(t, config.IMAP, cert, imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapUIDPlus: {}}, nil)
	config.IMAP.Address, config.IMAP.CAFile = address, ca
	inbox := mailboxID(config.AccountID, "INBOX")
	appendExternal := func(subject string, flags ...imap.Flag) *imap.AppendData {
		t.Helper()
		data, err := user.Append("INBOX", strings.NewReader("Subject: "+subject+"\r\n\r\nBody\r\n"),
			&imap.AppendOptions{Flags: flags, Time: time.Now()})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	target := appendExternal("Target", imap.FlagFlagged, imap.FlagSeen, imap.Flag("$seen"))
	marked := appendExternal("Unrelated marked message", imap.FlagDeleted)
	survivor := appendExternal("Unaffected")
	id := emailID(inbox, target.UIDValidity, target.UID)
	hidden := emailID(inbox, marked.UIDValidity, marked.UID)
	other := emailID(inbox, survivor.UIDValidity, survivor.UID)
	g, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	call := func(method string, args object) object {
		t.Helper()
		args["accountId"] = config.AccountID
		response := gatewayCalls(t, g, config.Token, [3]any{method, args, "mutation"})[0]
		if response.Name != method {
			t.Fatalf("%s returned %v", method, response)
		}
		return response.Args
	}
	state := call("Email/get", object{"ids": []string{hidden}, "properties": []string{"id"}})
	if !reflect.DeepEqual(state["notFound"], []any{hidden}) {
		t.Fatalf("marked IMAP message is visible: %v", state)
	}
	mailbox := func() map[string]any {
		t.Helper()
		return call("Mailbox/get", object{"ids": []string{inbox}})["list"].([]any)[0].(map[string]any)
	}
	if m := mailbox(); m["totalEmails"] != float64(2) || m["unreadEmails"] != float64(1) {
		t.Fatalf("deleted items affect mailbox counts: %v", m)
	}
	update := func(patch object, want ...string) {
		t.Helper()
		result := call("Email/set", object{"update": object{id: patch}})
		if result["notUpdated"] != nil {
			t.Fatalf("keyword patch %v failed: %v", patch, result)
		}
		read := call("Email/get", object{"ids": []string{id}, "properties": []string{"keywords"}})
		got := read["list"].([]any)[0].(map[string]any)["keywords"].(map[string]any)
		if !reflect.DeepEqual(sortedKeys(got), want) {
			t.Fatalf("keyword patch %v returned %v, want %v", patch, got, want)
		}
	}
	update(object{"keywords": object{"$answered": true, "$DRAFT": true, "ticket/1": true}}, "$answered", "$draft", "ticket/1")
	update(object{"keywords/$draft": nil, "keywords/$seen": true, "keywords/ticket~11": nil,
		"keywords/topic~0fix": true}, "$answered", "$seen", "topic~fix")
	update(object{"keywords/$seen": nil}, "$answered", "topic~fix")
	if m := mailbox(); m["unreadEmails"] != float64(2) {
		t.Fatalf("unread counter ignored the changed flags: %v", m)
	}
	update(object{"keywords": nil}, []string{}...)
	destroy := call("Email/set", object{"destroy": []string{id, "missing"}})
	if !reflect.DeepEqual(destroy["destroyed"], []any{id}) || destroy["notDestroyed"].(map[string]any)["missing"].(map[string]any)["type"] != "notFound" {
		t.Fatalf("destroy %v", destroy)
	}
	changes := call("Email/changes", object{"sinceState": state["state"]})
	if !reflect.DeepEqual(changes["destroyed"], []any{id}) || mailbox()["totalEmails"] != float64(1) {
		t.Fatalf("destroy didn't update state and counts: %v", changes)
	}
	result := call("Email/query", object{})
	if !reflect.DeepEqual(result["ids"], []any{other}) {
		t.Fatalf("unexpected survivor list: %v", result)
	}
	client, closeClient, err := g.connectIMAP(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer closeClient()
	selected, err := client.Select("INBOX", &imap.SelectOptions{ReadOnly: true}).Wait()
	if err != nil || selected.NumMessages != 2 {
		t.Fatalf("UID EXPUNGE affected another message: %v %v", selected, err)
	}
	if flags, failure := fetchEmailFlags(client, marked.UID); failure != "" || !flagPresent(flags, imap.FlagDeleted) {
		t.Fatalf("unrelated deletion flag was changed: %v %q", flags, failure)
	}
}

func TestEmailKeywordPatchValidationAndFlagPreservation(t *testing.T) {
	for _, raw := range []string{
		`null`, `[]`, `{"keywords":[]}`, `{"keywords":{"foo":false}}`, `{"keywords":{"Foo":true,"foo":true}}`,
		`{"keywords":{"foo":true},"keywords/bar":true}`, `{"keywords/$seen":false}`, `{"keywords/nested/path":true}`,
		`{"keywords/foo~2bar":true}`, `{"keywords/foo~":true}`, `{"keywords/invalid space":true}`, `{"keywords/":true}`,
	} {
		if result := (&operation{}).updateEmail("unused", json.RawMessage(raw)); result["type"] != "invalidPatch" {
			t.Fatalf("invalid keyword patch accepted: %s", raw)
		}
	}
	if patch, ok := keywordPatch(rawArgs(t, object{"keywords/foo~0bar~1test": true})); !ok || !patch.values["foo~bar/test"] {
		t.Fatalf("escaped pointer didn't resolve: %v %v", patch, ok)
	}
	if got := replacementFlags([]imap.Flag{`\Recent`, `\Vendor`, imap.FlagSeen, imap.Flag("$seen"), imap.Flag("custom")},
		keywordChange{replace: true, values: map[string]bool{"$draft": true}}); !reflect.DeepEqual(got, []imap.Flag{`\Vendor`, "$seen", imap.FlagDraft}) {
		t.Fatalf("STORE FLAGS lost an unmapped flag or tried to set Recent: %v", got)
	}
	if !supportsUIDExpunge(imap.CapSet{imap.CapIMAP4rev2: {}}) || supportsUIDExpunge(imap.CapSet{imap.CapIMAP4rev1: {}}) {
		t.Fatal("incorrect UID EXPUNGE capability detection")
	}
}

type expungeFaultSession struct {
	imapserver.Session
	fault            string
	marked, expunged bool
}

func (s *expungeFaultSession) Store(w *imapserver.FetchWriter, set imap.NumSet, flags *imap.StoreFlags, opts *imap.StoreOptions) error {
	if s.fault == "mark-denied" || s.fault == "rollback-denied" && flags.Op == imap.StoreFlagsDel {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeNoPerm}
	}
	if s.fault == "limit" {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeLimit}
	}
	if s.fault == "mark-ignored" || s.fault == "replace-ignored" {
		return nil
	}
	s.marked = flagPresent(flags.Flags, imap.FlagDeleted) && flags.Op == imap.StoreFlagsAdd
	return s.Session.Store(w, set, flags, opts)
}

func (s *expungeFaultSession) Fetch(w *imapserver.FetchWriter, set imap.NumSet, opts *imap.FetchOptions) error {
	if s.fault == "mark-confirmation" && s.marked || s.fault == "expunge-confirmation" && s.expunged || s.fault == "read-flags" {
		return fixtureIMAPError
	}
	return s.Session.Fetch(w, set, opts)
}

func (s *expungeFaultSession) Expunge(w *imapserver.ExpungeWriter, uids *imap.UIDSet) error {
	s.expunged = true
	if s.fault == "expunge-denied" || s.fault == "rollback-denied" {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeNoPerm}
	}
	if s.fault == "expunge-ignored" || s.fault == "expunge-confirmation" {
		return nil
	}
	return s.Session.Expunge(w, uids)
}

func TestEmailDestroyFailureAndKeywordConfirmation(t *testing.T) {
	cert, ca := testTLS(t)
	for _, tc := range []struct {
		fault, action, failure string
		hidden                 bool
	}{
		{"mark-denied", "destroy", "forbidden", false}, {"mark-ignored", "destroy", "forbidden", false},
		{"mark-confirmation", "destroy", "serverFail", true}, {"expunge-denied", "destroy", "forbidden", false},
		{"rollback-denied", "destroy", "forbidden", true}, {"expunge-ignored", "destroy", "serverFail", true},
		{"expunge-confirmation", "destroy", "serverFail", true}, {"read-flags", "destroy", "serverFail", false},
		{"uid-changed", "destroy", "notFound", true}, {"uid-missing", "destroy", "notFound", true},
		{"legacy", "destroy-method", "forbidden", false},
		{"limit", "keyword", "tooManyKeywords", false}, {"replace-ignored", "keyword", "forbidden", false},
		{"limit", "destroy", "serverFail", false},
		{"read-flags", "keyword", "serverFail", false}, {"pre-existing", "keyword", "notFound", false},
		{"pre-existing", "destroy", "", true},
	} {
		t.Run(tc.fault+"-"+tc.action, func(t *testing.T) {
			config := testConfig(t)
			caps := imap.CapSet{imap.CapIMAP4rev1: {}}
			if tc.fault != "legacy" {
				caps[imap.CapUIDPlus] = struct{}{}
			}
			address, user := serveTestIMAP(t, config.IMAP, cert, caps, func(session imapserver.Session) imapserver.Session {
				return &expungeFaultSession{Session: session, fault: tc.fault}
			})
			config.IMAP.Address, config.IMAP.CAFile = address, ca
			var flags []imap.Flag
			if tc.fault == "pre-existing" {
				flags = append(flags, imap.FlagDeleted)
			}
			msg, err := user.Append("INBOX", strings.NewReader("Subject: Fixture\r\n\r\n"),
				&imap.AppendOptions{Time: time.Now(), Flags: flags})
			if err != nil {
				t.Fatal(err)
			}
			g, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			defer g.Close()
			client, closeClient, err := g.connectIMAP(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer closeClient()
			meta := &emailMeta{ID: "fixture", Path: "INBOX", UID: msg.UID, Validity: msg.UIDValidity}
			if tc.fault == "uid-changed" {
				meta.Validity++
			}
			if tc.fault == "uid-missing" {
				meta.UID++
			}
			hidden, failure := false, ""
			switch tc.action {
			case "keyword":
				_, failure = storeEmailKeywords(client, meta, keywordChange{replace: true, values: map[string]bool{"$seen": true}})
			case "destroy-method":
				op := operation{g: g, client: client, snapshot: &snapshot{emails: map[string]*emailMeta{meta.ID: meta}}}
				failure = op.destroyEmail(meta.ID)
			default:
				hidden, failure = expungeEmail(client, meta)
			}
			if hidden != tc.hidden || failure != tc.failure {
				t.Fatalf("got hidden=%t error=%q, want %t %q", hidden, failure, tc.hidden, tc.failure)
			}
			if tc.fault == "expunge-denied" {
				flags, failure := fetchEmailFlags(client, meta.UID)
				if failure != "" || flagPresent(flags, imap.FlagDeleted) {
					t.Fatalf("tagged EXPUNGE rejection left a deletion mark: %v %q", flags, failure)
				}
			}
		})
	}
}
