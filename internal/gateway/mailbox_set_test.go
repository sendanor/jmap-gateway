package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
)

func TestMailboxSetHierarchyAndStableIDs(t *testing.T) {
	config := testConfig(t)
	cert, ca := testTLS(t)
	address, user := serveTestIMAP(t, config.IMAP, cert, imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapListExtended: {}}, func(session imapserver.Session) imapserver.Session {
		return subtreeFixtureSession{session}
	})
	config.IMAP.Address, config.IMAP.CAFile = address, ca
	g, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	request := func(method string, args object, code string) object {
		t.Helper()
		args["accountId"] = config.AccountID
		result := gatewayCalls(t, g, config.Token, [3]any{method, args, "mailbox-set"})[0]
		if code == "" && result.Name != method || code != "" && (result.Name != "error" || result.Args["type"] != code) {
			t.Fatalf("%s %v returned %v, want %s", method, args, result, code)
		}
		return result.Args
	}
	set := func(args object) object { return request("Mailbox/set", args, "") }
	typeOf := func(result object, group, id string) any {
		t.Helper()
		if failures, ok := result[group].(map[string]any); ok {
			if entry, ok := failures[id].(map[string]any); ok {
				return entry["type"]
			}
		}
		t.Fatalf("expected %s for %s: %v", group, id, result)
		return nil
	}
	before := request("Mailbox/get", object{}, "")["state"]
	created := set(object{"ifInState": before, "create": object{
		"child":   object{"name": "Notes", "parentId": "#parent", "isSubscribed": false, "sortOrder": 8},
		"parent":  object{"name": "Projects", "sortOrder": 2},
		"cycle-a": object{"name": "A", "parentId": "#cycle-b"},
		"cycle-b": object{"name": "B", "parentId": "#cycle-a"},
	}})
	createdRows := created["created"].(map[string]any)
	parent := createdRows["parent"].(map[string]any)["id"].(string)
	child := createdRows["child"].(map[string]any)["id"].(string)
	if typeOf(created, "notCreated", "cycle-a") != "invalidProperties" ||
		createdRows["parent"].(map[string]any)["isSubscribed"] != true || createdRows["child"].(map[string]any)["parentId"] != parent {
		t.Fatalf("create hierarchy: %v", created)
	}
	request("Mailbox/set", object{"ifInState": before}, "stateMismatch")
	msg, err := user.Append("Projects/Notes", strings.NewReader("Subject: Protected\r\n\r\nBody\r\n"), &imap.AppendOptions{Time: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	email := emailID(child, msg.UIDValidity, msg.UID)
	if result := set(object{"destroy": []string{parent, child, "unknown", mailboxID(config.AccountID, "INBOX")}}); typeOf(result, "notDestroyed", parent) != "mailboxHasChild" ||
		typeOf(result, "notDestroyed", child) != "mailboxHasEmail" || typeOf(result, "notDestroyed", "unknown") != "notFound" ||
		typeOf(result, "notDestroyed", mailboxID(config.AccountID, "INBOX")) != "forbidden" {
		t.Fatalf("guarded destroys: %v", result)
	}
	if result := set(object{"update": object{parent: object{"parentId": child}}}); typeOf(result, "notUpdated", parent) != "invalidProperties" {
		t.Fatalf("moving a mailbox below its own child: %v", result)
	}
	beforeRename := request("Mailbox/get", object{}, "")["state"]
	queryArgs := object{"sort": []object{{"property": "sortOrder", "isAscending": false}}}
	query := request("Mailbox/query", queryArgs, "")
	if query["ids"].([]any)[0] != child {
		t.Fatalf("initial sort order: %v", query)
	}
	if result := set(object{"update": object{parent: object{"name": "Archive Work", "sortOrder": 20, "isSubscribed": false}}}); result["notUpdated"] != nil {
		t.Fatalf("rename parent: %v", result)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	g = reopened
	list := request("Mailbox/get", object{"ids": []string{parent, child}}, "")["list"].([]any)
	if list[0].(map[string]any)["name"] != "Archive Work" || list[0].(map[string]any)["sortOrder"] != float64(20) ||
		list[1].(map[string]any)["parentId"] != parent || list[0].(map[string]any)["isSubscribed"] != false {
		t.Fatalf("restart persistence: %v", list)
	}
	if body := request("Email/get", object{"ids": []string{email}}, "")["list"].([]any); len(body) != 1 {
		t.Fatalf("renamed descendant lost original email ID: %v", body)
	}
	changes := request("Mailbox/changes", object{"sinceState": beforeRename}, "")
	if !reflect.DeepEqual(changes["updated"], []any{parent, child}) && !reflect.DeepEqual(changes["updated"], []any{child, parent}) {
		t.Fatalf("rename should update original IDs: %v", changes)
	}
	queryArgs["sinceQueryState"] = query["queryState"]
	if result := request("Mailbox/queryChanges", queryArgs, ""); len(result["added"].([]any)) == 0 || result["added"].([]any)[0].(map[string]any)["id"] != parent {
		t.Fatalf("sortOrder update missing from delta: %v", result)
	}
	if result := set(object{"update": object{child: object{"parentId": nil, "isSubscribed": true}}}); result["notUpdated"] != nil {
		t.Fatalf("reparent to root: %v", result)
	}
	if result := set(object{"update": object{child: object{"isSubscribed": false}, parent: object{}}}); result["notUpdated"] != nil {
		t.Fatalf("unsubscribe and no-op: %v", result)
	}
	if result := set(object{"destroy": []string{parent}}); !reflect.DeepEqual(result["destroyed"], []any{parent}) {
		t.Fatalf("remove empty mailbox: %v", result)
	}
	if result := set(object{"destroy": []string{child}, "onDestroyRemoveEmails": true}); !reflect.DeepEqual(result["destroyed"], []any{child}) {
		t.Fatalf("remove mailbox and contents: %v", result)
	}
	if err := user.Create("Projects", nil); err != nil {
		t.Fatal(err)
	}
	if result := request("Mailbox/get", object{"ids": []string{parent}}, ""); !reflect.DeepEqual(result["notFound"], []any{parent}) {
		t.Fatalf("reused path resurrected destroyed ID: %v", result)
	}
}

type mailboxFaultSession struct {
	imapserver.Session
	fault string
}

// The memory server only renames the exact path. Model the IMAP-required
// recursive rename for the known child in this fixture.
type subtreeFixtureSession struct{ imapserver.Session }

func (s subtreeFixtureSession) Rename(path, target string, options *imap.RenameOptions) error {
	if err := s.Session.Rename(path, target, options); err != nil {
		return err
	}
	if path == "Projects" {
		return s.Session.Rename(path+"/Notes", target+"/Notes", options)
	}
	return nil
}

func (s mailboxFaultSession) Create(path string, options *imap.CreateOptions) error {
	if s.fault == "create" {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeOverQuota}
	}
	return s.Session.Create(path, options)
}

func (s mailboxFaultSession) Subscribe(path string) error {
	if s.fault == "subscribe" {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeNoPerm}
	}
	return s.Session.Subscribe(path)
}

func (s mailboxFaultSession) Rename(path, target string, options *imap.RenameOptions) error {
	if s.fault == "rename" {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeAlreadyExists}
	}
	return s.Session.Rename(path, target, options)
}

func (s mailboxFaultSession) Status(path string, options *imap.StatusOptions) (*imap.StatusData, error) {
	if s.fault == "status" {
		return nil, &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeNonExistent}
	}
	status, err := s.Session.Status(path, options)
	if err == nil && s.fault == "stale" {
		status.UIDValidity++
	}
	return status, err
}

func (s mailboxFaultSession) Delete(path string) error {
	if s.fault == "delete" {
		return &imap.Error{Type: imap.StatusResponseTypeNo}
	}
	return s.Session.Delete(path)
}

func (s mailboxFaultSession) Unsubscribe(path string) error {
	if s.fault == "vanished" {
		return s.Session.Delete(path)
	}
	return s.Session.Unsubscribe(path)
}

func TestMailboxSetUpstreamFailures(t *testing.T) {
	cert, ca := testTLS(t)
	for _, tc := range []struct{ fault, action, want string }{
		{"create", "create", "overQuota"}, {"subscribe", "create", "forbidden"},
		{"subscribe", "update", "forbidden"}, {"rename", "rename", "invalidProperties"},
		{"subscribe", "rename", "forbidden"}, {"status", "destroy", "notFound"},
		{"delete", "destroy", "serverFail"}, {"stale", "destroy", "serverFail"},
		{"disk", "rename", "serverFail"}, {"disk", "update", "serverFail"}, {"disk", "create", "serverFail"},
		{"vanished", "create", "serverFail"},
	} {
		t.Run(tc.fault+"-"+tc.action, func(t *testing.T) {
			config := testConfig(t)
			address, user := serveTestIMAP(t, config.IMAP, cert, imap.CapSet{imap.CapIMAP4rev1: {}}, func(session imapserver.Session) imapserver.Session {
				return mailboxFaultSession{Session: session, fault: tc.fault}
			})
			config.IMAP.Address, config.IMAP.CAFile = address, ca
			if err := user.Create("Project", nil); err != nil {
				t.Fatal(err)
			}
			g, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			defer g.Close()
			if tc.fault == "disk" {
				original := g.ledger.files.rename
				g.ledger.files.rename = func(source, target string) error {
					if filepath.Base(target) == mailboxStateFile {
						return errors.New("fixture write rejection")
					}
					return original(source, target)
				}
			}
			id := mailboxID(config.AccountID, "Project")
			args := object{"accountId": config.AccountID}
			group := "notUpdated"
			switch tc.action {
			case "create":
				group, id = "notCreated", "new"
				args["create"] = object{id: object{"name": "Work", "isSubscribed": tc.fault != "vanished"}}
			case "update":
				args["update"] = object{id: object{"isSubscribed": true}}
			case "rename":
				args["update"] = object{id: object{"name": "Work", "isSubscribed": true}}
			case "destroy":
				group = "notDestroyed"
				args["destroy"] = []string{id}
			}
			result := gatewayCalls(t, g, config.Token, [3]any{"Mailbox/set", args, "fail"})[0]
			if result.Name != "Mailbox/set" || result.Args[group].(map[string]any)[id].(map[string]any)["type"] != tc.want {
				t.Fatalf("failed IMAP operation returned %v, want %s", result, tc.want)
			}
		})
	}
	if mailboxIMAPError(io.EOF)["type"] != "serverUnavailable" {
		t.Fatal("IMAP transport error classified as a tagged rejection")
	}
}

func TestMailboxSetSnapshotAndRenameFailures(t *testing.T) {
	cert, ca := testTLS(t)
	for _, action := range []string{"create", "update", "destroy", "rename"} {
		t.Run(action, func(t *testing.T) {
			config := testConfig(t)
			address, user := serveTestIMAP(t, config.IMAP, cert, imap.CapSet{imap.CapIMAP4rev1: {}}, nil)
			config.IMAP.Address, config.IMAP.CAFile = address, ca
			if err := user.Create("Project", nil); err != nil {
				t.Fatal(err)
			}
			g, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			defer g.Close()
			id := mailboxID(config.AccountID, "Project")
			if action == "rename" {
				op := operation{g: g, ctx: context.Background()}
				if failure := op.loadMail(); failure != "" {
					t.Fatal(failure)
				}
				defer op.closeIMAP()
				b := op.snapshot.mailbox(id)
				_ = op.client.Close()
				if failure := op.renameMailbox(b, mailboxUpdate{path: "New", delimiter: '/'}); failure["type"] != "serverUnavailable" {
					t.Fatalf("ambiguous rename: %v", failure)
				}
				if state, failure := g.loadMailboxState(); failure != "" || len(state.Rename) != 1 {
					t.Fatalf("ambiguous rename lost its journal: %v %q", state, failure)
				}
				return
			}
			originalRename := g.ledger.files.rename
			g.ledger.files.rename = func(source, target string) error {
				if filepath.Base(target) == mailboxStateFile {
					return os.WriteFile(target, []byte(`{"Details":null}`), 0600)
				}
				return originalRename(source, target)
			}
			args := object{"accountId": config.AccountID}
			switch action {
			case "create":
				args["create"] = object{"new": object{"name": "New"}}
			case "update":
				args["update"] = object{id: object{"sortOrder": 5}}
			case "destroy":
				args["destroy"] = []string{id}
			}
			result := gatewayCalls(t, g, config.Token, [3]any{"Mailbox/set", args, "fault"})[0]
			if result.Name != "error" || result.Args["type"] != "serverFail" {
				t.Fatalf("lost snapshot after %s returned %v", action, result)
			}
		})
	}
}

func TestMailboxCreateSpecialUseAndRenameCollision(t *testing.T) {
	config := testConfig(t)
	cert, ca := testTLS(t)
	address, user := serveTestIMAP(t, config.IMAP, cert, imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapCreateSpecialUse: {}}, nil)
	config.IMAP.Address, config.IMAP.CAFile = address, ca
	for _, path := range []string{"Old", "Old/Child", "New/Child"} {
		if err := user.Create(path, nil); err != nil {
			t.Fatal(err)
		}
	}
	g, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	op := operation{g: g, ctx: context.Background()}
	if failure := op.loadMail(); failure != "" {
		t.Fatal(failure)
	}
	defer op.closeIMAP()
	if failure := op.renameMailbox(op.snapshot.mailbox(mailboxID(config.AccountID, "Old")), mailboxUpdate{path: "New", delimiter: '/'}); failure["type"] != "invalidProperties" {
		t.Fatalf("rename overwrote an existing descendant: %v", failure)
	}
	if _, failure := op.createMailbox(rawArgs(t, object{"name": "Invalid", "role": "unknown"})); failure["type"] != "invalidProperties" {
		t.Fatalf("unknown role: %v", failure)
	}
	op.snapshot.mailbox(mailboxID(config.AccountID, "Old")).Role = "archive"
	if _, failure := op.createMailbox(rawArgs(t, object{"name": "Duplicate", "role": "archive"})); failure["type"] != "invalidProperties" {
		t.Fatalf("duplicate account role: %v", failure)
	}
	if _, failure := op.createMailbox(rawArgs(t, object{"name": "Trash", "role": "trash"})); failure != nil {
		t.Fatalf("CREATE with SPECIAL-USE: %v", failure)
	}
}

func TestMailboxRenameRecoveryAndCorruptState(t *testing.T) {
	config := testConfig(t)
	cert, ca := testTLS(t)
	address, user := serveTestIMAP(t, config.IMAP, cert, imap.CapSet{imap.CapIMAP4rev1: {}}, nil)
	config.IMAP.Address, config.IMAP.CAFile = address, ca
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
	if err := user.Create("Old", nil); err != nil {
		t.Fatal(err)
	}
	initial, failure := g.scan(client)
	if failure != "" {
		t.Fatal(failure)
	}
	old := initial.mailbox(mailboxID(config.AccountID, "Old"))
	pending := mailboxState{Details: map[string]mailboxDetails{}, Rename: []mailboxRenameEntry{
		{From: "Old", To: "New", Validity: old.Validity, Details: mailboxDetails{ID: old.ID, SortOrder: 7}},
	}}
	if failure := g.saveMailboxState(pending); failure != "" {
		t.Fatal(failure)
	}
	if result, failure := g.scan(client); failure != "" || result.mailbox(old.ID).Path != "Old" {
		t.Fatalf("unexecuted rename: %s %v", failure, result)
	}
	if failure := g.saveMailboxState(pending); failure != "" {
		t.Fatal(failure)
	}
	if err := client.Rename("Old", "New", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	if result, failure := g.scan(client); failure != "" || result.mailbox(old.ID).Path != "New" || result.mailbox(old.ID).SortOrder != 7 {
		t.Fatalf("executed rename: %s %v", failure, result)
	}
	if failure := g.saveMailboxState(pending); failure != "" {
		t.Fatal(failure)
	}
	if err := user.Create("Old", nil); err != nil {
		t.Fatal(err)
	}
	if _, failure := g.scan(client); failure != "serverFail" {
		t.Fatalf("ambiguous rename returned %q", failure)
	}
	if err := user.Delete("Old"); err != nil {
		t.Fatal(err)
	}
	pending.Rename[0].Validity++
	if failure := g.saveMailboxState(pending); failure != "" {
		t.Fatal(failure)
	}
	if _, failure := g.scan(client); failure != "serverFail" {
		t.Fatalf("mismatched UIDVALIDITY returned %q", failure)
	}
	path := filepath.Join(config.StateDir, mailboxStateFile)
	if err := os.WriteFile(path, []byte(`{"Details":null}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, failure := g.scan(client); failure != "serverFail" {
		t.Fatalf("corrupt state returned %q", failure)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(mailboxStateFile, path); err != nil {
		t.Fatal(err)
	}
	if _, failure := g.loadMailboxState(); failure != "serverFail" {
		t.Fatalf("state open error returned %q", failure)
	}
}

func TestMailboxSetInvalidProperties(t *testing.T) {
	g, err := New(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	inbox := &box{ID: "inbox", Path: "INBOX", Name: "INBOX", Role: "inbox"}
	if _, failure := (&operation{g: g, snapshotFailure: "serverUnavailable"}).setMailboxes(nil); failure != "serverUnavailable" {
		t.Fatalf("unavailable IMAP returned %q", failure)
	}
	op := operation{g: g, created: map[string]string{"known": "id"}, snapshot: &snapshot{
		boxes: []*box{inbox}, rootDelimiter: '/', paths: map[string]bool{"INBOX": true}, emails: make(map[string]*emailMeta),
	}}
	for _, tc := range []object{
		{"name": "bad/path"}, {"name": nil}, {"name": "a\u0300"}, {"name": "a\r"}, {"name": strings.Repeat("x", 256)},
		{"name": "INBOX"}, {"name": "folder", "parentId": "#missing"}, {"name": "folder", "parentId": true},
		{"name": "folder", "role": ""}, {"name": "folder", "role": 1}, {"name": "folder", "sortOrder": 1 << 31},
		{"name": "folder", "isSubscribed": nil}, {"name": "folder", "id": "server-set"},
	} {
		if _, result := op.mailboxUpdate(nil, rawArgs(t, tc)); result == nil || result["type"] != "invalidProperties" {
			t.Fatalf("invalid property %v returned %v", tc, result)
		}
	}
	if _, result := op.createMailbox(nil); result["type"] != "invalidProperties" {
		t.Fatalf("creation without a name: %v", result)
	}
	if _, result := op.mailboxUpdate(nil, rawArgs(t, object{"name": "child", "parentId": "inbox"})); result["type"] != "forbidden" {
		t.Fatalf("read-only parent: %v", result)
	}
	for _, tc := range []struct {
		input object
		want  string
	}{
		{object{"onDestroyRemoveEmails": "yes"}, "invalidArguments"},
		{object{"destroy": make([]string, maxSet+1)}, "requestTooLarge"},
		{object{"create": object{"invalid!": object{}}}, "invalidArguments"},
	} {
		if _, failure := op.setMailboxes(rawArgs(t, tc.input)); failure != tc.want {
			t.Fatalf("set %v returned %q, want %q", tc.input, failure, tc.want)
		}
	}
	for _, tc := range []struct{ id, patch, want string }{
		{"missing", `{}`, "notFound"}, {"inbox", `true`, "invalidPatch"},
		{"inbox", `{"role":null}`, "invalidProperties"}, {"inbox", `{"name":"Other"}`, "forbidden"},
	} {
		if result := op.updateMailbox(tc.id, json.RawMessage(tc.patch)); result["type"] != tc.want {
			t.Fatalf("update %v: %v", tc, result)
		}
	}
	for i := range maxMailboxes {
		op.snapshot.paths[fmt.Sprint(i)] = true
	}
	if _, errorObject := op.createMailbox(rawArgs(t, object{"name": "folder"})); errorObject["type"] != "overQuota" {
		t.Fatalf("mailbox quota: %v", errorObject)
	}
}
