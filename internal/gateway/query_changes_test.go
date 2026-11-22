package gateway

import (
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
)

func TestEmailQueryChangesWithSparseCacheAndRestart(t *testing.T) {
	config := testConfig(t)
	cert, ca := testTLS(t)
	config.IMAP.CAFile = ca
	address, user := serveTestIMAP(t, config.IMAP, cert, imap.CapSet{imap.CapIMAP4rev1: {}}, nil)
	config.IMAP.Address = address
	account := config.AccountID
	add := func(path string, day int) string {
		t.Helper()
		now := time.Date(2026, 10, day, 8, 0, 0, 0, time.UTC)
		appended, err := user.Append(path, strings.NewReader("Subject: Window\r\n\r\nBody\r\n"), &imap.AppendOptions{Time: now})
		if err != nil {
			t.Fatal(err)
		}
		return emailID(mailboxID(account, path), appended.UIDValidity, appended.UID)
	}
	first := add("INBOX", 3)
	anchor := add("INBOX", 5)
	removed := add("Drafts", 6)
	g, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	get := func(method string, args object) (string, object) {
		t.Helper()
		args["accountId"] = account
		result := gatewayCalls(t, g, config.Token, [3]any{method, args, "query"})[0]
		return result.Name, result.Args
	}
	order := []object{{"property": "receivedAt"}}
	_, original := get("Email/query", object{"limit": 2, "sort": order})
	if !reflect.DeepEqual(original["ids"], []any{first, anchor}) || original["canCalculateChanges"] != true {
		t.Fatalf("initial query: %v", original)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	g, err = New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	older := add("INBOX", 2)
	newer := add("INBOX", 7)
	if err := user.Delete("Drafts"); err != nil {
		t.Fatal(err)
	}
	method, sparse := get("Email/queryChanges", object{
		"sinceQueryState": original["queryState"], "sort": []object{{"property": "receivedAt", "isAscending": true}},
		"upToId": anchor, "maxChanges": 1, "calculateTotal": true,
	})
	if method != "Email/queryChanges" || len(sparse["removed"].([]any)) != 0 ||
		!reflect.DeepEqual(sparse["added"], []any{map[string]any{"id": older, "index": float64(0)}}) ||
		sparse["total"] != float64(4) {
		t.Fatalf("bad sparse changes: %v", sparse)
	}
	name, full := get("Email/queryChanges", object{"sort": order, "sinceQueryState": original["queryState"], "upToId": "missing"})
	if name != "Email/queryChanges" || !reflect.DeepEqual(full["removed"], []any{removed}) ||
		!reflect.DeepEqual(full["added"], []any{map[string]any{"id": older, "index": float64(0)}, map[string]any{"id": newer, "index": float64(3)}}) ||
		full["total"] != nil {
		t.Fatalf("bad complete changes: %v", full)
	}
	_, latest := get("Email/query", object{"sort": order})
	if full["oldQueryState"] != original["queryState"] || full["newQueryState"] != latest["queryState"] {
		t.Fatal("change state did not match ordinary query")
	}
	name, unchanged := get("Email/queryChanges", object{"sinceQueryState": latest["queryState"], "sort": order, "maxChanges": 0})
	if name != "Email/queryChanges" || unchanged["newQueryState"] != latest["queryState"] ||
		len(unchanged["removed"].([]any))+len(unchanged["added"].([]any)) != 0 {
		t.Fatalf("unchanged query with zero change budget returned %v", unchanged)
	}
	for _, check := range []struct {
		method string
		args   object
		kind   string
	}{
		{"Email/queryChanges", object{"sinceQueryState": original["queryState"], "sort": order, "maxChanges": 2}, "tooManyChanges"},
		{"Email/queryChanges", object{"sinceQueryState": original["queryState"], "sort": []object{{"property": "receivedAt", "isAscending": false}}}, "cannotCalculateChanges"},
		{"Mailbox/queryChanges", object{"sinceQueryState": original["queryState"]}, "cannotCalculateChanges"},
		{"Email/queryChanges", object{"sinceQueryState": "missing", "sort": order}, "cannotCalculateChanges"},
		{"Email/queryChanges", object{"sinceQueryState": original["queryState"], "maxChanges": -1}, "invalidArguments"},
		{"Email/queryChanges", object{"sinceQueryState": original["queryState"], "upToId": "bad id"}, "invalidArguments"},
		{"Email/queryChanges", object{"sinceQueryState": original["queryState"], "sort": []object{{"property": "bogus"}}}, "unsupportedSort"},
		{"Email/query", object{"sortAsTree": false}, "invalidArguments"},
	} {
		method, response := get(check.method, check.args)
		if method != "error" || response["type"] != check.kind {
			t.Fatalf("%s returned %s %v, want %s", check.method, method, response, check.kind)
		}
	}
}

func TestMailboxQueryChangesReinsertsMutableMatches(t *testing.T) {
	config := testConfig(t)
	cert, ca := testTLS(t)
	config.IMAP.CAFile = ca
	addr, user := serveTestIMAP(t, config.IMAP, cert, imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapListExtended: {}}, nil)
	config.IMAP.Address = addr
	g, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	account := config.AccountID
	query := object{"accountId": account, "sort": []object{{"property": "name"}},
		"filter": object{"operator": "OR", "conditions": []object{{"isSubscribed": true}, {"isSubscribed": false}}}}
	original := gatewayCalls(t, g, config.Token, [3]any{"Mailbox/query", query, "query"})[0]
	drafts := mailboxID(account, "Drafts")
	if err := user.Unsubscribe("Drafts"); err != nil {
		t.Fatal(err)
	}
	if err := user.Create("ZZZ", nil); err != nil {
		t.Fatal(err)
	}
	query["sinceQueryState"] = original.Args["queryState"]
	query["upToId"] = mailboxID(account, "Drafts/Child")
	delta := gatewayCalls(t, g, config.Token, [3]any{"Mailbox/queryChanges", query, "delta"})[0]
	if delta.Name != "Mailbox/queryChanges" || !reflect.DeepEqual(delta.Args["removed"], []any{drafts}) ||
		!reflect.DeepEqual(delta.Args["added"], []any{
			map[string]any{"id": drafts, "index": float64(1)},
			map[string]any{"id": mailboxID(account, "ZZZ"), "index": float64(4)},
		}) {
		t.Fatalf("mutable query did not reinsert changed mailbox: %v", delta)
	}
}

func TestQueryDifferenceKeepsCompleteDeltaWhenRowsCrossAnchor(t *testing.T) {
	before := []queryRow{{ID: "first"}, {ID: "anchor"}, {ID: "last"}}
	after := []queryRow{{ID: "last"}, {ID: "anchor"}, {ID: "first"}, {ID: "new"}}
	expectedRemoved, expectedAdded := queryDifference(before, after, "")
	removed, added := queryDifference(before, after, "anchor")
	if !slices.Equal(removed, expectedRemoved) || !slices.Equal(added, expectedAdded) {
		t.Fatalf("anchor clipped a reordered query: removed %v, added %v", removed, added)
	}
}

func TestQueryDifferenceReconstructsCompleteResults(t *testing.T) {
	random := rand.New(rand.NewPCG(41, 6))
	for count := range 180 {
		idCount := 2 + count%25
		makeRows := func() []queryRow {
			rows := make([]queryRow, 0, idCount)
			for _, i := range random.Perm(idCount) {
				if random.IntN(4) != 0 {
					rows = append(rows, queryRow{ID: fmt.Sprint(i), Revision: fmt.Sprint(random.IntN(5) / 4)})
				}
			}
			return rows
		}
		before, after := makeRows(), makeRows()
		removed, added := queryDifference(before, after, "")
		result, want := []string{}, []string{}
		for _, row := range before {
			if !slices.Contains(removed, row.ID) {
				result = append(result, row.ID)
			}
		}
		for _, insertion := range added {
			result = slices.Insert(result, insertion.Index, insertion.ID)
		}
		for _, row := range after {
			want = append(want, row.ID)
		}
		if !slices.Equal(result, want) {
			t.Fatalf("old %v, new %v, removed %v, added %v, reconstructed %v", before, after, removed, added, result)
		}
	}
}

func TestQueryHistoryPersistenceFailureAndCapacity(t *testing.T) {
	cache := queryHistory{dir: t.TempDir(), files: localAtomicFiles}
	path := filepath.Join(cache.dir, queryHistoryFile)
	if err := os.WriteFile(path, []byte("{corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	failing := true
	cache.files.rename = func(src, dst string) error {
		if failing {
			return diskError
		}
		return localAtomicFiles.rename(src, dst)
	}
	a := queryObservation{State: "a", Rows: []queryRow{{ID: "one"}}}
	cache.remember(a)
	if !cache.dirty || cache.find("a") != 0 {
		t.Fatal("failed write should keep query available in memory")
	}
	failing = false
	cache.remember(a)
	if cache.dirty {
		t.Fatal("an unchanged query did not retry a failed write")
	}
	cache.remember(queryObservation{State: "b", Rows: []queryRow{{ID: "two"}}})
	cache.remember(a)
	reopened := queryHistory{dir: cache.dir, files: localAtomicFiles}
	if reopened.find("a") != 1 || reopened.find("b") != 0 {
		t.Fatal("history did not retain recent ordering across reload")
	}
	reopened.observations = make([]queryObservation, maxQuerySnapshots+1)
	reopened.observations[0].State = "expired"
	reopened.trim()
	if len(reopened.observations) != maxQuerySnapshots || reopened.find("expired") >= 0 {
		t.Fatal("snapshot capacity ignored")
	}
	reopened.observations = []queryObservation{{State: "expired", Rows: make([]queryRow, maxQueryRows)}, a}
	reopened.trim()
	if len(reopened.observations) != 1 || reopened.find("expired") >= 0 {
		t.Fatal("row capacity ignored")
	}
}

func TestBoundQueryReferencesAndCanonicalFilters(t *testing.T) {
	config := testConfig(t)
	g, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	op := operation{g: g, created: map[string]string{"selection": "drafts", "old": "e-mail"}}
	rows := []queryRow{{ID: "match"}}
	observed := func(kind, raw string) string {
		t.Helper()
		var input queryDefinition
		if !decodeStrict([]byte(raw), &input) {
			t.Fatal("test definition invalid")
		}
		return op.queryObservation(kind, input, rows).State
	}
	if observed("Mailbox", `{"filter":{"operator":"AND","conditions":[{"parentId":"#selection","role":null}]}}`) !=
		observed("Mailbox", `{"filter":{"conditions":[{"role":null,"parentId":"drafts"}],"operator":"AND"},"sort":[]}`) {
		t.Fatal("identical query parameters generated distinct keys")
	}
	first := observed("EmailSubmission", `{"filter":{"emailIds":["#old"]}}`)
	op.created["old"] = "e-other"
	if first == observed("EmailSubmission", `{"filter":{"emailIds":["#old"]}}`) {
		t.Fatal("query state crossed between disparate creation bindings")
	}
}
