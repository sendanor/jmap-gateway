package gateway

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
)

func TestEmailQueryMetadataAndComparators(t *testing.T) {
	g, err := New(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	date := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	op := operation{g: g, created: map[string]string{"included": "inbox"}, snapshot: &snapshot{emails: map[string]*emailMeta{
		"a": {ID: "a", MailboxID: "inbox", Received: date, Size: 20, ThreadID: "shared", Keywords: map[string]bool{"$seen": true}},
		"b": {ID: "b", MailboxID: "drafts", Received: date.Add(time.Minute), Size: 40, ThreadID: "shared"},
		"c": {ID: "c", MailboxID: "inbox", Received: date.Add(2 * time.Minute), Size: 40},
	}}}
	for _, test := range []struct {
		args object
		want string
	}{
		{object{"filter": object{"inMailboxOtherThan": []string{"#included"}}}, "b"},
		{object{"filter": object{"before": "2026-11-22T12:02:00Z", "after": "2026-11-22T12:00:00Z", "minSize": 20, "maxSize": 40}}, "a"},
		{object{"filter": object{"operator": "OR", "conditions": []object{
			{"hasKeyword": "$SEEN"}, {"noneInThreadHaveKeyword": "$seen"},
		}}}, "c,a"},
		{object{"filter": object{"operator": "NOT", "conditions": []object{{"notKeyword": "$seen"}, {"allInThreadHaveKeyword": "$seen"}}}}, "a"},
		{object{"filter": object{"someInThreadHaveKeyword": "$seen"}}, "b,a"},
		{object{"sort": []object{{"property": "size"}, {"property": "receivedAt"}}}, "a,b,c"},
		{object{"sort": []object{{"property": "hasKeyword", "keyword": "$seen", "isAscending": false}}}, "a,c,b"},
		{object{"sort": []object{{"property": "allInThreadHaveKeyword", "keyword": "$seen"}}}, "c,b,a"},
	} {
		result, failure := op.query(rawArgs(t, test.args))
		if failure != "" || strings.Join(result["ids"].([]string), ",") != test.want {
			t.Fatalf("query %v returned %v, %s, want %s", test.args, result, failure, test.want)
		}
	}
	for _, args := range []object{
		{"filter": object{"inMailboxOtherThan": nil}},
		{"filter": object{"inMailboxOtherThan": []string{"#missing"}}},
		{"filter": object{"before": "2026-11-22T12:00:00+00:00"}},
		{"filter": object{"after": "invalidZ"}},
		{"filter": object{"minSize": -1}},
		{"filter": object{"maxSize": 1 << 53}},
		{"filter": object{"hasKeyword": "with spaces"}},
		{"sort": []object{{"property": "hasKeyword"}}},
		{"sort": []object{{"property": "size", "keyword": "$seen"}}},
	} {
		if _, failure := op.query(rawArgs(t, args)); failure != "invalidArguments" {
			t.Fatalf("query %v returned %q", args, failure)
		}
	}
	if _, failure := op.queryMailboxes(rawArgs(t, object{"sort": []object{{"property": "name", "keyword": "$seen"}}})); failure != "invalidArguments" {
		t.Fatalf("mailbox comparing a keyword returned %q", failure)
	}
	// Even when no other key distinguishes two rows, their order is stable.
	op.snapshot.emails["d"] = &emailMeta{ID: "d", MailboxID: "inbox", Received: date, Size: 20}
	result, failure := op.query(rawArgs(t, object{"sort": []object{{"property": "size"}}}))
	if failure != "" || !reflect.DeepEqual(result["ids"], []string{"a", "d", "c", "b"}) {
		t.Fatalf("tied comparator returned %v, %q", result, failure)
	}
}

func TestEmailQueryKeywordChangeFromAnotherMailbox(t *testing.T) {
	config := testConfig(t)
	cert, ca := testTLS(t)
	address, user := serveTestIMAP(t, config.IMAP, cert, imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapUIDPlus: {}}, nil)
	config.IMAP.Address, config.IMAP.CAFile = address, ca
	appendEmail := func(mailbox, headers string, minute int) string {
		t.Helper()
		message, err := user.Append(mailbox, strings.NewReader(headers+"\r\n\r\nTest message\r\n"),
			&imap.AppendOptions{Time: time.Date(2026, 11, 22, 12, minute, 0, 0, time.UTC)})
		if err != nil {
			t.Fatal(err)
		}
		return emailID(mailboxID(config.AccountID, mailbox), message.UIDValidity, message.UID)
	}
	root := appendEmail("INBOX", "Subject: Work\r\nMessage-ID: <root@test>", 1)
	reply := appendEmail("Drafts", "Subject: Re: Work\r\nReferences: <root@test>", 2)
	other := appendEmail("INBOX", "Subject: Independent", 3)
	g, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	call := func(method string, args object) (string, object) {
		t.Helper()
		args["accountId"] = config.AccountID
		result := gatewayCalls(t, g, config.Token, [3]any{method, args, "query"})[0]
		return result.Name, result.Args
	}
	filter := object{"inMailbox": mailboxID(config.AccountID, "INBOX")}
	order := []object{{"property": "someInThreadHaveKeyword", "keyword": "$seen"}}
	name, before := call("Email/query", object{"sort": order, "filter": filter})
	if name != "Email/query" || !reflect.DeepEqual(before["ids"], []any{other, root}) {
		t.Fatalf("initial query returned %s %v", name, before)
	}
	name, updated := call("Email/set", object{"update": object{reply: object{"keywords/$seen": true}}})
	if name != "Email/set" || updated["updated"] == nil {
		t.Fatalf("seen update: %s, %v", name, updated)
	}
	name, delta := call("Email/queryChanges", object{
		"sinceQueryState": before["queryState"], "sort": order, "filter": filter, "upToId": other,
	})
	if name != "Email/queryChanges" || !reflect.DeepEqual(delta["removed"], []any{root}) ||
		!reflect.DeepEqual(delta["added"], []any{map[string]any{"id": root, "index": float64(1)}}) {
		t.Fatalf("thread keyword change must replace the stable index: %s %v", name, delta)
	}
	name, mismatch := call("Email/queryChanges", object{
		"sinceQueryState": before["queryState"], "filter": filter,
		"sort": []object{{"property": "someInThreadHaveKeyword", "keyword": "$flagged"}},
	})
	if name != "error" || mismatch["type"] != "cannotCalculateChanges" {
		t.Fatalf("query token accepted another sort keyword: %s %v", name, mismatch)
	}
}
