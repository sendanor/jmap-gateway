package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-imap/v2/imapserver"
)

func TestEmailMovePreservesIDsAcrossRestart(t *testing.T) {
	config := testConfig(t)
	cert, ca := testTLS(t)
	address, user := serveTestIMAP(t, config.IMAP, cert, imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapUIDPlus: {}, imap.CapMove: {}}, nil)
	config.IMAP.Address, config.IMAP.CAFile = address, ca
	msg, err := user.Append("INBOX", strings.NewReader("Subject: Move fixture\r\n\r\nBody\r\n"),
		&imap.AppendOptions{Time: time.Now(), Flags: []imap.Flag{imap.FlagSeen}})
	if err != nil {
		t.Fatal(err)
	}
	inbox, plain := mailboxID(config.AccountID, "INBOX"), mailboxID(config.AccountID, "Plain")
	id := emailID(inbox, msg.UIDValidity, msg.UID)
	g, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	call := func(method string, args object) object {
		t.Helper()
		args["accountId"] = config.AccountID
		response := gatewayCalls(t, g, config.Token, [3]any{method, args, "move"})[0]
		if response.Name != method {
			t.Fatalf("%s %v returned %v", method, args, response)
		}
		return response.Args
	}
	read := func(folder string) object {
		t.Helper()
		result := call("Email/get", object{"ids": []string{id}, "properties": []string{"id", "blobId", "threadId", "mailboxIds", "subject", "keywords"}})
		list := result["list"].([]any)
		if len(list) != 1 {
			t.Fatalf("Email id missing after move: %v", result)
		}
		entry := list[0].(map[string]any)
		if entry["id"] != id || entry["subject"] != "Move fixture" || entry["threadId"] != threadID(id, "") || entry["blobId"] != "b-"+id[2:] ||
			!reflect.DeepEqual(entry["mailboxIds"], map[string]any{folder: true}) || !reflect.DeepEqual(entry["keywords"], map[string]any{"$seen": true}) {
			t.Fatalf("Email projection changed unexpectedly: %v", entry)
		}
		return result
	}
	before := read(inbox)
	filter := object{"inMailboxOtherThan": []string{"unrelated"}}
	query := call("Email/query", object{"filter": filter})
	move := call("Email/set", object{"ifInState": before["state"], "update": object{id: object{
		"mailboxIds/" + inbox: nil, "mailboxIds/" + plain: true,
	}}})
	if move["notUpdated"] != nil || move["newState"] == move["oldState"] {
		t.Fatalf("move failure: %v", move)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	g = reopened
	read(plain)
	delta := call("Email/changes", object{"sinceState": before["state"]})
	if !reflect.DeepEqual(delta["updated"], []any{id}) || len(delta["created"].([]any)) != 0 || len(delta["destroyed"].([]any)) != 0 {
		t.Fatalf("move must update one durable id: %v", delta)
	}
	window := call("Email/queryChanges", object{"filter": filter, "sinceQueryState": query["queryState"]})
	if !reflect.DeepEqual(window["removed"], []any{id}) || !reflect.DeepEqual(window["added"], []any{map[string]any{"id": id, "index": float64(0)}}) {
		t.Fatalf("mailbox filter needs a replacement at the same index: %v", window)
	}
	set := func(change object) object { return call("Email/set", object{"update": object{id: change}}) }
	if combined := set(object{"mailboxIds": object{inbox: true}, "keywords/$answered": true}); combined["notUpdated"] != nil {
		t.Fatalf("combined move and keyword update failed: %v", combined)
	}
	readBack := call("Email/get", object{"ids": []string{id}, "properties": []string{"mailboxIds", "keywords"}})["list"].([]any)[0].(map[string]any)
	if !reflect.DeepEqual(readBack["mailboxIds"], map[string]any{inbox: true}) || readBack["keywords"].(map[string]any)["$answered"] != true {
		t.Fatalf("combined mutation did not reach the destination: %v", readBack)
	}
	if reset := set(object{"mailboxIds": object{plain: true}, "keywords/$answered": nil}); reset["notUpdated"] != nil {
		t.Fatalf("restore folder and flags: %v", reset)
	}
	read(plain)
	if noOp := set(object{"mailboxIds": object{plain: true}, "keywords/$seen": true}); noOp["notUpdated"] != nil {
		t.Fatalf("patch with the current mailbox: %v", noOp)
	}
	responses := gatewayCalls(t, g, config.Token,
		[3]any{"Mailbox/set", object{"accountId": config.AccountID, "create": object{"folder": object{"name": "Moved"}}}, "create"},
		[3]any{"Email/set", object{"accountId": config.AccountID, "update": object{id: object{"mailboxIds": object{"#folder": true}}}}, "move"})
	if responses[1].Name != "Email/set" || responses[1].Args["notUpdated"] != nil {
		t.Fatalf("move to a mailbox creation reference: %v", responses)
	}
	newID := responses[0].Args["created"].(map[string]any)["folder"].(map[string]any)["id"].(string)
	read(newID)
	if state, failure := g.loadEmailMoves(); failure != "" || len(state.Aliases) != 1 || state.Pending != nil {
		t.Fatalf("repeated move left stale aliases: %+v %q", state, failure)
	}
}

func TestEmailQueryTieSurvivesMailboxMove(t *testing.T) {
	cfg := testConfig(t)
	cert, ca := testTLS(t)
	address, user := serveTestIMAP(t, cfg.IMAP, cert, imap.CapSet{
		imap.CapIMAP4rev1: {}, imap.CapUIDPlus: {}, imap.CapMove: {},
	}, nil)
	cfg.IMAP.Address, cfg.IMAP.CAFile = address, ca
	date := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	appendAt := func(folder string, received time.Time) string {
		t.Helper()
		added, err := user.Append(folder, strings.NewReader("Subject: Tied\r\n\r\nBody\r\n"),
			&imap.AppendOptions{Time: received})
		if err != nil {
			t.Fatal(err)
		}
		return emailID(mailboxID(cfg.AccountID, folder), added.UIDValidity, added.UID)
	}
	earlierUID, laterUID := appendAt("INBOX", date), appendAt("INBOX", date)
	inbox, destination := mailboxID(cfg.AccountID, "INBOX"), mailboxID(cfg.AccountID, "Plain")
	moving := earlierUID
	if inbox < destination {
		moving = laterUID
	}
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	call := func(method string, args object) object {
		t.Helper()
		args["accountId"] = cfg.AccountID
		result := gatewayCalls(t, g, cfg.Token, [3]any{method, args, "query"})[0]
		if result.Name != method {
			t.Fatalf("%s returned %v", method, result)
		}
		return result.Args
	}
	order := []object{{"property": "receivedAt", "isAscending": false}}
	want := []any{min(earlierUID, laterUID), max(earlierUID, laterUID)}
	before := call("Email/query", object{"sort": order})
	if !reflect.DeepEqual(before["ids"], want) {
		t.Fatalf("tied rows were not ordered by ID: %v", before)
	}
	moved := call("Email/set", object{"update": object{
		moving: object{"mailboxIds": object{destination: true}},
	}})
	if moved["notUpdated"] != nil {
		t.Fatalf("move failed: %v", moved)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	g, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	after := call("Email/query", object{"sort": order, "anchor": want[1], "anchorOffset": -1})
	if !reflect.DeepEqual(after["ids"], want) || after["queryState"] != before["queryState"] {
		t.Fatalf("the move changed the tied query: %v", after)
	}
	newest := appendAt("INBOX", date.Add(time.Minute))
	appendAt("INBOX", date.Add(-time.Minute))
	delta := call("Email/queryChanges", object{
		"sort": order, "sinceQueryState": before["queryState"], "upToId": want[1], "maxChanges": 1,
	})
	if len(delta["removed"].([]any)) != 0 || !reflect.DeepEqual(delta["added"], []any{map[string]any{"id": newest, "index": float64(0)}}) {
		t.Fatalf("unexpected sparse delta after crossing folders: %v", delta)
	}
}

type moveFaultSession struct {
	imapserver.SessionMove
	fault string
	moved bool
}

func (s *moveFaultSession) Move(w *imapserver.MoveWriter, set imap.NumSet, dest string) error {
	if s.fault == "reject" {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeNoPerm}
	}
	if s.fault == "no-copyuid" {
		return nil
	}
	if err := s.SessionMove.Move(w, set, dest); err != nil {
		return err
	}
	s.moved = true
	switch s.fault {
	case "partial":
		return &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeNoPerm}
	case "vanish":
		return s.SessionMove.Delete(dest)
	}
	return nil
}

func (s *moveFaultSession) Fetch(w *imapserver.FetchWriter, set imap.NumSet, opts *imap.FetchOptions) error {
	if s.moved && s.fault == "refresh" {
		return fixtureIMAPError
	}
	return s.SessionMove.Fetch(w, set, opts)
}

func (s *moveFaultSession) Store(w *imapserver.FetchWriter, set imap.NumSet, flags *imap.StoreFlags, opts *imap.StoreOptions) error {
	if s.moved && s.fault == "store" {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeNoPerm}
	}
	return s.SessionMove.Store(w, set, flags, opts)
}

func (s *moveFaultSession) Status(path string, opts *imap.StatusOptions) (*imap.StatusData, error) {
	if s.fault == "status" {
		return nil, fixtureIMAPError
	}
	return s.SessionMove.Status(path, opts)
}

func TestEmailMoveFailureAndRecovery(t *testing.T) {
	cert, ca := testTLS(t)
	for _, tc := range []struct{ mode, result, scanAfter string }{
		{"no-move", "forbidden", ""}, {"stale-source", "notFound", ""}, {"missing-source", "notFound", ""},
		{"status", "serverFail", ""}, {"stale-target", "serverFail", ""},
		{"disk-intent", "serverFail", ""}, {"reject", "forbidden", ""},
		{"no-copyuid", "serverFail", ""}, {"partial", "forbidden", "serverFail"},
		{"disk-result", "serverFail", ""}, {"refresh", "serverFail", "serverFail"},
		{"vanish", "notFound", ""}, {"store", "forbidden", ""},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			config := testConfig(t)
			caps := imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapUIDPlus: {}}
			if tc.mode != "no-move" {
				caps[imap.CapMove] = struct{}{}
			}
			address, user := serveTestIMAP(t, config.IMAP, cert, caps, func(session imapserver.Session) imapserver.Session {
				return &moveFaultSession{SessionMove: session.(imapserver.SessionMove), fault: tc.mode}
			})
			config.IMAP.Address, config.IMAP.CAFile = address, ca
			msg, err := user.Append("INBOX", strings.NewReader("Subject: Move fixture\r\n\r\nBody\r\n"), &imap.AppendOptions{Time: time.Now()})
			if err != nil {
				t.Fatal(err)
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
			id := emailID(mailboxID(config.AccountID, "INBOX"), msg.UIDValidity, msg.UID)
			meta := op.snapshot.emails[id]
			target := op.snapshot.mailbox(mailboxID(config.AccountID, "Plain"))
			switch tc.mode {
			case "stale-source":
				meta.Validity++
			case "missing-source":
				meta.UID++
			case "stale-target":
				target.Validity++
			case "disk-intent", "disk-result":
				original := g.ledger.files.rename
				writes := 0
				g.ledger.files.rename = func(source, target string) error {
					if filepath.Base(target) == emailMovesFile {
						writes++
						if tc.mode == "disk-intent" || writes == 2 || writes == 3 {
							return errors.New("fixture disk failure")
						}
					}
					return original(source, target)
				}
			}
			if tc.mode == "no-copyuid" {
				result, failure := op.set("Email", rawArgs(t, object{"update": object{
					id: object{"mailboxIds": object{target.ID: true}}, "later": object{"keywords/$seen": true},
				}, "destroy": []string{id}}))
				if failure != "" || result["notUpdated"].(object)[id].(object)["type"] != tc.result ||
					result["notUpdated"].(object)["later"].(object)["type"] != "serverFail" ||
					result["notDestroyed"].(object)[id].(object)["type"] != "serverFail" {
					t.Fatalf("ambiguous move must stop later mutations in the same batch: %v %q", result, failure)
				}
			} else if tc.mode == "store" {
				patch, err := json.Marshal(object{"mailboxIds": object{target.ID: true}, "keywords/$seen": true})
				if err != nil {
					t.Fatal(err)
				}
				if failure := op.updateEmail(id, patch); failure["type"] != tc.result {
					t.Fatalf("failure after confirmed move: %v", failure)
				}
			} else if failure := op.moveEmail(meta, target); failure != tc.result {
				t.Fatalf("move failure: %q, want %q", failure, tc.result)
			}
			if tc.mode == "disk-result" {
				if _, failure := g.scan(op.client); failure != "serverFail" {
					t.Fatalf("temporarily unflushed mapping returned %q", failure)
				}
			}
			fresh, failure := g.scan(op.client)
			if failure != tc.scanAfter {
				t.Fatalf("scan after failed move: %q, want %q", failure, tc.scanAfter)
			}
			if tc.mode == "disk-result" && (fresh.emails[id] == nil || fresh.emails[id].MailboxID != target.ID) {
				t.Fatalf("could not recover acknowledged mapping after disk recovery: %v", fresh)
			}
			if tc.mode == "store" && (fresh.emails[id] == nil || fresh.emails[id].MailboxID != target.ID || fresh.emails[id].Keywords["$seen"]) {
				t.Fatalf("failed flag update lost the confirmed destination or changed flags: %v", fresh.emails[id])
			}
		})
	}
}

func TestEmailMailboxPatchAndMoveJournalValidation(t *testing.T) {
	op := operation{snapshot: &snapshot{boxes: []*box{{ID: "source"}, {ID: "dest"}},
		emails: map[string]*emailMeta{"email": {ID: "email", MailboxID: "source"}}}, created: map[string]string{"target": "dest"}}
	for _, tc := range []struct{ patch, want string }{
		{`{"mailboxIds":null}`, "invalidPatch"}, {`{"mailboxIds":{"dest":true},"mailboxIds/source":null}`, "invalidPatch"},
		{`{"mailboxIds":{"dest":false}}`, "invalidProperties"}, {`{"mailboxIds":{"absent":true}}`, "invalidProperties"},
		{`{"mailboxIds/dest":false}`, "invalidPatch"}, {`{"mailboxIds/nested/bad":true}`, "invalidPatch"},
		{`{"mailboxIds/dest":true,"mailboxIds/#target":true}`, "invalidPatch"},
		{`{"mailboxIds/absent":true}`, "invalidProperties"}, {`{"mailboxIds/dest":true}`, "tooManyMailboxes"},
		{`{"mailboxIds/source":null}`, "invalidProperties"},
	} {
		if result := op.updateEmail("email", json.RawMessage(tc.patch)); result["type"] != tc.want {
			t.Fatalf("patch %s returned %v, want %q", tc.patch, result, tc.want)
		}
	}
	for _, response := range []*imapclient.MoveData{
		nil, {}, {UIDValidity: 2}, {UIDValidity: 2, SourceUIDs: imap.UIDSetNum(1), DestUIDs: imap.UIDSetNum(2, 3)},
		{UIDValidity: 2, SourceUIDs: imap.UIDSetNum(3), DestUIDs: imap.UIDSetNum(5)},
	} {
		if movedUID(response, 1) != 0 {
			t.Fatalf("invalid COPYUID response accepted: %v", response)
		}
	}
	g, err := New(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	path := filepath.Join(g.config.StateDir, emailMovesFile)
	if err := os.WriteFile(path, []byte(`{"Aliases":null}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, failure := g.loadEmailMoves(); failure != "serverFail" {
		t.Fatalf("corrupt move journal accepted: %q", failure)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(emailMovesFile, path); err != nil {
		t.Fatal(err)
	}
	if _, failure := g.loadEmailMoves(); failure != "serverFail" {
		t.Fatalf("journal open error returned %q", failure)
	}
}
