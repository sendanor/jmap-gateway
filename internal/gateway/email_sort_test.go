package gateway

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
)

func TestEmailQueryHeaderSortAndChanges(t *testing.T) {
	config := testConfig(t)
	cert, ca := testTLS(t)
	address, user := serveTestIMAP(t, config.IMAP, cert, imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapUIDPlus: {}}, nil)
	config.IMAP.Address, config.IMAP.CAFile = address, ca
	appendExternal := func(receivedMinute int, header string) string {
		t.Helper()
		// These messages exceed the raw body budget. The header sort reads
		// only the header section.
		raw := header + "\r\n\r\n" + strings.Repeat("body line\r\n", maxRaw/10+1)
		msg, err := user.Append("INBOX", strings.NewReader(raw), &imap.AppendOptions{
			Time: time.Date(2026, 11, 22, 12, receivedMinute, 0, 0, time.UTC),
		})
		if err != nil {
			t.Fatal(err)
		}
		return emailID(mailboxID(config.AccountID, "INBOX"), msg.UIDValidity, msg.UID)
	}
	a := appendExternal(1, "From: zebra@test\r\nTo: A Zi <z@test>\r\nSubject: [fwd: Re [2]: [list] alpha (fwd)] (fwd)\r\nDate: 22 Nov 2026 12:00:00 +0200")
	b := appendExternal(2, "From: Bravo <aaa@test>, A Second <second@test>\r\nTo: m@test\r\nSubject: Beta\r\nDate: 22 Nov 2026 09:00:00 +0000")
	c := appendExternal(3, "Subject: rE: =?UTF-8?Q?ALPHA?=\r\nDate: malformed")
	d := appendExternal(4, "From: =?UTF-8?Q?=C3=84nne?= <first@test>\r\nTo: ZZZ <first@test>\r\nSubject: [only]\r\nDate: 22 Nov 2026 09:00:00 -0030")
	g, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	call := func(method string, args object) (string, object) {
		t.Helper()
		args["accountId"] = config.AccountID
		response := gatewayCalls(t, g, config.Token, [3]any{method, args, "sort"})[0]
		return response.Name, response.Args
	}
	check := func(sort []object, ids ...string) object {
		t.Helper()
		name, result := call("Email/query", object{"sort": sort})
		want := make([]any, len(ids))
		for i, id := range ids {
			want[i] = id
		}
		if name != "Email/query" || !reflect.DeepEqual(result["ids"], want) {
			t.Fatalf("sort %v returned %s %v, want %v", sort, name, result, want)
		}
		return result
	}
	check([]object{{"property": "from"}}, c, d, b, a)
	check([]object{{"property": "from", "collation": asciiCasemap}}, c, b, a, d)
	check([]object{{"property": "to", "isAscending": false}}, d, b, a, c)
	check([]object{{"property": "sentAt", "collation": "ignored"}}, c, b, d, a)
	check([]object{{"property": "sentAt", "isAscending": false}}, a, d, b, c)
	check([]object{{"property": "subject", "collation": octetCollation}}, c, b, d, a)
	order := []object{{"property": "subject", "collation": asciiCasemap}, {"property": "sentAt", "isAscending": false}}
	before := check(order, a, c, b, d)
	if name, result := call("Email/query", object{"sort": []object{{"property": "subject", "collation": "unknown"}}}); name != "error" || result["type"] != "unsupportedSort" {
		t.Fatalf("unknown collation: %s %v", name, result)
	}
	// An unneeded MIME branch cannot make header sorting read oversized bodies.
	name, filtered := call("Email/query", object{"sort": order, "filter": object{"operator": "OR", "conditions": []object{
		{"minSize": maxRaw}, {"body": "word"},
	}}})
	if name != "Email/query" || !reflect.DeepEqual(filtered["ids"], before["ids"]) {
		t.Fatalf("header sort with short-circuited body filter: %s %v", name, filtered)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	added := appendExternal(5, "Subject: Fw: Aardvark")
	g, err = New(config)
	if err != nil {
		t.Fatal(err)
	}
	name, delta := call("Email/queryChanges", object{"sort": order, "sinceQueryState": before["queryState"]})
	if name != "Email/queryChanges" || !reflect.DeepEqual(delta["added"], []any{map[string]any{"id": added, "index": float64(0)}}) ||
		len(delta["removed"].([]any)) != 0 {
		t.Fatalf("subject sort delta: %s %v", name, delta)
	}
	if latest := check(order, added, a, c, b, d); delta["newQueryState"] != latest["queryState"] {
		t.Fatalf("subject sort state differs after applying delta: %v", delta)
	}
	name, mismatch := call("Email/queryChanges", object{"sort": []object{{"property": "subject", "collation": octetCollation}, order[1]}, "sinceQueryState": before["queryState"]})
	if name != "error" || mismatch["type"] != "cannotCalculateChanges" {
		t.Fatalf("another collation accepted the query state: %s %v", name, mismatch)
	}
}

func TestBaseSubjectAndQueryCollations(t *testing.T) {
	for _, test := range []struct{ input, want string }{
		{"  [list]\t [project] fWd [two] : Re[4]:  café\r\n\tde Paris (fwd) (FWD) ", "café de Paris"},
		{"[Fwd: [fwd: Re: [list] =?UTF-8?Q?R=C3=A9union?=] (fwd)]", "Réunion"},
		{"Re: [first] [only]", "[only]"},
		{"[notice] Re:", ""},
		{"[fwd:]", ""},
		{"Fwd: =?unknown?Q?Literal?=", "=?unknown?Q?Literal?="},
		{"Recreation: Journal", "Recreation: Journal"},
	} {
		if got := baseSubject(test.input); got != test.want {
			t.Fatalf("base subject for %q = %q, want %q", test.input, got, test.want)
		}
	}
	ascii := queryStringComparator(asciiCasemap)
	octet := queryStringComparator(octetCollation)
	if ascii("Z", "a") <= 0 || octet("Z", "a") >= 0 || ascii("aZ", "Az") != 0 ||
		ascii("ä", "Ä") == 0 || ascii("prefix", "prefix-b") >= 0 {
		t.Fatal("ASCII and octet collations do not order prefix, case, or non-ASCII correctly")
	}
	unicode := queryStringComparator("")
	if unicode("ä", "Ä") != 0 || unicode("Ä", "a\u0308") != 0 || unicode("Änne", "Bravo") >= 0 {
		t.Fatal("default collation did not handle Unicode case, canonical equivalence, or alphabetic order")
	}
}
