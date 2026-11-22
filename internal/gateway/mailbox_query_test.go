package gateway

import (
	"reflect"
	"testing"

	"github.com/emersion/go-imap/v2"
)

func TestMailboxQueryTreeFiltersAndPaging(t *testing.T) {
	config := testConfig(t)
	config.DraftsMailbox = "Drafts"
	cert, ca := testTLS(t)
	config.IMAP.CAFile = ca
	addr, user := serveTestIMAP(t, config.IMAP, cert, imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapListExtended: {}}, nil)
	config.IMAP.Address = addr
	if err := user.Create("Drafts/Ääni", nil); err != nil {
		t.Fatal(err)
	}
	g, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	get := func(fields object) object {
		t.Helper()
		fields["accountId"] = config.AccountID
		result := gatewayCalls(t, g, config.Token, [3]any{"Mailbox/query", fields, "query"})[0]
		if result.Name != "Mailbox/query" {
			t.Fatalf("mailbox query failed: %v", result)
		}
		return result.Args
	}
	check := func(args object, names ...string) object {
		t.Helper()
		result := get(args)
		want := make([]any, 0, len(names))
		for _, name := range names {
			want = append(want, mailboxID(config.AccountID, name))
		}
		if !reflect.DeepEqual(result["ids"], want) {
			t.Fatalf("mailbox query returned %v, expected %v", result["ids"], want)
		}
		return result
	}
	sortName := []object{{"property": "sortOrder", "collation": "ignored"}, {"property": "name"}}
	check(object{"sort": sortName}, "Drafts/Ääni", "Drafts/Child", "Drafts", "INBOX", "Plain")
	check(object{"sort": []object{{"property": "name", "collation": asciiCasemap}}}, "Drafts/Child", "Drafts", "INBOX", "Plain", "Drafts/Ääni")
	check(object{"sort": sortName, "sortAsTree": true}, "Drafts", "Drafts/Ääni", "Drafts/Child", "INBOX", "Plain")
	check(object{"sort": []object{{"property": "name", "isAscending": false}}, "sortAsTree": true},
		"Plain", "INBOX", "Drafts", "Drafts/Child", "Drafts/Ääni")
	query := object{
		"sort": sortName, "sortAsTree": true, "filterAsTree": true,
		"filter": object{"operator": "OR", "conditions": []object{
			{"operator": "AND", "conditions": []object{{"hasAnyRole": true}, {"isSubscribed": true}}},
			{"parentId": mailboxID(config.AccountID, "Drafts")},
			{"operator": "NOT", "conditions": []object{{"role": nil}}},
		}},
	}
	check(query, "Drafts", "Drafts/Ääni", "Drafts/Child", "INBOX")
	check(object{"filter": object{"name": "ÄÄNI"}}, "Drafts/Ääni")
	check(object{"filter": object{"name": "ÄÄNI"}, "filterAsTree": true})
	check(object{"filter": object{"parentId": nil, "role": "drafts"}}, "Drafts")
	check(object{"filter": object{"hasAnyRole": false, "isSubscribed": false, "parentId": nil}}, "Plain")
	win := check(object{"sort": sortName, "position": -2, "limit": 1, "calculateTotal": true}, "INBOX")
	if win["position"] != float64(3) || win["total"] != float64(5) || win["limit"] != nil ||
		win["canCalculateChanges"] != true {
		t.Fatalf("incorrect window: %v", win)
	}
	pastEnd := check(object{"sort": sortName, "position": 100})
	if pastEnd["position"] != float64(100) {
		t.Fatalf("out-of-range position was clamped: %v", pastEnd)
	}
	around := check(object{"sort": sortName, "anchor": mailboxID(config.AccountID, "Drafts"),
		"anchorOffset": -1, "position": 99, "limit": 2}, "Drafts/Child", "Drafts")
	if around["position"] != float64(1) || around["total"] != nil {
		t.Fatalf("incorrect anchor window: %v", around)
	}
}

func TestMailboxQueryInvalidArgumentsAndFilters(t *testing.T) {
	config := testConfig(t)
	g, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	op := operation{g: g, snapshot: &snapshot{boxes: []*box{{ID: "root"}, {ID: "child", ParentID: "root"}}},
		created: map[string]string{"known": "root"}}
	nested := object{}
	for range 34 {
		nested = object{"operator": "NOT", "conditions": []object{nested}}
	}
	for _, test := range []struct {
		args object
		want string
	}{
		{object{"limit": -1}, "invalidArguments"},
		{object{"position": int64(1 << 53)}, "invalidArguments"},
		{object{"sort": []object{{"property": "role"}}}, "unsupportedSort"},
		{object{"sort": []object{{"property": "name", "collation": "unknown"}}}, "unsupportedSort"},
		{object{"filter": object{"unimplemented": true}}, "unsupportedFilter"},
		{object{"filter": object{"operator": "XOR", "conditions": []object{}}}, "invalidArguments"},
		{object{"filter": object{"operator": "AND", "conditions": []any{nil}}}, "invalidArguments"},
		{object{"filter": object{"operator": "NOT", "conditions": []object{{"unimplemented": false}}}}, "unsupportedFilter"},
		{object{"filter": nested}, "unsupportedFilter"},
		{object{"filter": object{"role": ""}}, "invalidArguments"},
		{object{"filter": object{"parentId": "#missing"}}, "invalidArguments"},
		{object{"filter": object{"name": nil}}, "invalidArguments"},
		{object{"filter": object{"isSubscribed": 12}}, "invalidArguments"},
		{object{"anchor": "missing"}, "anchorNotFound"},
	} {
		if _, failure := op.queryMailboxes(rawArgs(t, test.args)); failure != test.want {
			t.Fatalf("query returned %q, want %q", failure, test.want)
		}
	}
	var opFilter = object{"filter": object{"parentId": "#known"}}
	if result, failure := op.queryMailboxes(rawArgs(t, opFilter)); failure != "" ||
		!reflect.DeepEqual(result["ids"], []string{"child"}) {
		t.Fatalf("parent reference failed: %v, %q", result, failure)
	}
	op.snapshot, op.snapshotFailure = nil, "serverUnavailable"
	if _, failure := op.queryMailboxes(rawArgs(t, object{})); failure != "serverUnavailable" {
		t.Fatalf("upstream outage propagated as %q", failure)
	}
}
