package gateway

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
)

func TestThreadSynchronizationAndCollapsedQueries(t *testing.T) {
	config := testConfig(t)
	cert, ca := testTLS(t)
	address, user := serveTestIMAP(t, config.IMAP, cert, imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapUIDPlus: {}}, nil)
	config.IMAP.Address, config.IMAP.CAFile = address, ca
	date := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	appendExternal := func(folder, headers string, elapsed time.Duration, flags ...imap.Flag) string {
		t.Helper()
		msg, err := user.Append(folder, strings.NewReader(headers+"\r\n\r\nThis message stays on IMAP.\r\n"),
			&imap.AppendOptions{Time: date.Add(elapsed), Flags: flags})
		if err != nil {
			t.Fatal(err)
		}
		return emailID(mailboxID(config.AccountID, folder), msg.UIDValidity, msg.UID)
	}
	reply := appendExternal("Drafts", "Subject: Re: [list] Project status\r\nMessage-ID: <reply@test>\r\nIn-Reply-To: <original@test>", time.Minute)
	g, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	call := func(name string, args object) object {
		t.Helper()
		args["accountId"] = config.AccountID
		response := gatewayCalls(t, g, config.Token, [3]any{name, args, "tag"})[0]
		if response.Name != name {
			t.Fatalf("%s: %v", name, response)
		}
		return response.Args
	}
	item := func(result object) map[string]any {
		t.Helper()
		list := result["list"].([]any)
		if len(list) != 1 {
			t.Fatalf("expected one object: %v", result)
		}
		return list[0].(map[string]any)
	}
	thread := item(call("Email/get", object{"ids": []string{reply}, "properties": []string{"threadId"}}))["threadId"].(string)
	threads := call("Thread/get", object{"ids": []string{thread, "unknown"}})
	if !reflect.DeepEqual(item(threads)["emailIds"], []any{reply}) || !reflect.DeepEqual(threads["notFound"], []any{"unknown"}) {
		t.Fatalf("initial thread: %v", threads)
	}
	state := threads["state"]
	query := call("Email/query", object{"collapseThreads": true})
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	root := appendExternal("INBOX", "Subject: Project status\r\nMessage-ID: <original@test>", 0, imap.FlagSeen)
	last := appendExternal("INBOX", "Subject: Fwd: Project   status\r\nReferences: <original@test>\r\n <reply@test>", 2*time.Minute, imap.FlagSeen)
	other := appendExternal("INBOX", "Subject: Different topic\r\nIn-Reply-To: <original@test>", 3*time.Minute, imap.FlagSeen)
	g, err = New(config)
	if err != nil {
		t.Fatal(err)
	}
	changes := call("Thread/changes", object{"sinceState": state})
	if !reflect.DeepEqual(changes["updated"], []any{thread}) || len(changes["created"].([]any)) != 1 {
		t.Fatalf("thread changes: %v", changes)
	}
	updated := item(call("Thread/get", object{"ids": []string{thread}, "properties": []string{"emailIds"}}))
	if !reflect.DeepEqual(updated["emailIds"], []any{root, reply, last}) || len(updated) != 2 {
		t.Fatalf("chronological thread membership: %v", updated)
	}
	window := call("Email/query", object{"collapseThreads": true, "calculateTotal": true})
	if !reflect.DeepEqual(window["ids"], []any{other, last}) || window["total"] != float64(2) {
		t.Fatalf("incorrect collapsed results: %v", window)
	}
	delta := call("Email/queryChanges", object{"collapseThreads": true, "sinceQueryState": query["queryState"]})
	if !reflect.DeepEqual(delta["removed"], []any{reply}) || delta["newQueryState"] != window["queryState"] ||
		!reflect.DeepEqual(delta["added"], []any{map[string]any{"id": other, "index": float64(0)}, map[string]any{"id": last, "index": float64(1)}}) {
		t.Fatalf("incorrect collapsed delta: %v", delta)
	}
	for _, test := range []struct {
		name string
		args object
		code string
	}{
		{"Email/queryChanges", object{"sinceQueryState": query["queryState"]}, "cannotCalculateChanges"},
		{"Mailbox/query", object{"collapseThreads": true}, "invalidArguments"},
	} {
		test.args["accountId"] = config.AccountID
		response := gatewayCalls(t, g, config.Token, [3]any{test.name, test.args, "error"})[0]
		if response.Name != "error" || response.Args["type"] != test.code {
			t.Fatalf("%s: %v", test.name, response)
		}
	}
	inbox := mailboxID(config.AccountID, "INBOX")
	mailbox := call("Mailbox/get", object{"ids": []string{inbox}})
	counts := item(mailbox)
	if counts["totalEmails"] != float64(3) || counts["totalThreads"] != float64(2) ||
		counts["unreadEmails"] != float64(0) || counts["unreadThreads"] != float64(1) {
		t.Fatalf("related unread email in another folder must count toward unread threads: %v", counts)
	}
	call("Email/set", object{"update": object{reply: object{"keywords/$seen": true}}})
	countsDelta := call("Mailbox/changes", object{"sinceState": mailbox["state"]})
	if !reflect.DeepEqual(countsDelta["updatedProperties"], []any{"unreadEmails", "unreadThreads"}) {
		t.Fatalf("count-only changes: %v", countsDelta)
	}
	if err := user.Delete("Drafts"); err != nil {
		t.Fatal(err)
	}
	removed := call("Thread/changes", object{"sinceState": changes["newState"]})
	if !reflect.DeepEqual(removed["updated"], []any{thread}) {
		t.Fatalf("removing a member must update the thread: %v", removed)
	}
	if err := user.Delete("INBOX"); err != nil {
		t.Fatal(err)
	}
	destroyed := call("Thread/changes", object{"sinceState": removed["newState"]})
	if len(destroyed["destroyed"].([]any)) != 2 {
		t.Fatalf("empty threads must be destroyed: %v", destroyed)
	}
}

func TestThreadHeaderBoundsAndMailboxCounts(t *testing.T) {
	subject := "Subject: =?utf-8?Q?R=C3=A9union?=\r\nMessage-ID: <root@test>\r\n\r\n"
	thread := threadForMessage("account", []byte(subject))
	if thread == "" || thread == threadForMessage("other", []byte(subject)) ||
		thread != threadForMessage("account", []byte("Subject: Re: réunion\r\nReferences: <root@test>\r\n\r\n")) {
		t.Fatal("incorrect normalized subject or account scope")
	}
	for _, raw := range []string{
		"malformed", "Subject: " + strings.Repeat("x", maxThreadHeaders) + "\r\nMessage-ID: <root@test>\r\n\r\n",
		"Subject: =?bogus?Q?R?=\r\n\r\n",
	} {
		if threadForMessage("account", []byte(raw)) != "" {
			t.Fatal("malformed, oversized or unreferenced header assigned a shared thread")
		}
	}
	if threadForMessage("account", []byte("Subject: =?bogus?Q?R?=\r\nMessage-ID: <root@test>\r\n\r\n")) == "" {
		t.Fatal("undecodable subject should still use its literal value")
	}
	s := &snapshot{boxes: []*box{{ID: "a"}, {ID: "z", Role: "trash"}}, emails: map[string]*emailMeta{
		"c":     {ID: "c", MailboxID: "z", ThreadID: thread},
		"b":     {ID: "b", MailboxID: "a", ThreadID: thread, Keywords: map[string]bool{"$seen": true}},
		"a":     {ID: "a", MailboxID: "a", ThreadID: thread, Keywords: map[string]bool{"$seen": true}},
		"stale": {ID: "stale", MailboxID: "missing"},
	}}
	s.countMailboxes()
	if s.boxes[0].UnreadThreads != 0 || s.boxes[1].UnreadThreads != 1 ||
		!reflect.DeepEqual(s.threads()[thread], []string{"a", "b", "c"}) {
		t.Fatalf("incorrect trash handling or equal-date ordering: %v, %v", s.boxes, s.threads())
	}
	for i := range maxGet {
		id := fmt.Sprintf("e-%d", i)
		s.emails[id] = &emailMeta{ID: id}
	}
	g, err := New(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	op := operation{g: g, snapshot: s}
	if _, failure := op.get("Thread", nil); failure != "requestTooLarge" {
		t.Fatalf("unbounded Thread/get returned %q", failure)
	}
}
