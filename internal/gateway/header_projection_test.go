package gateway

import (
	"net/mail"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
)

func TestEmailHeaderProjectionsAcrossReadAndParse(t *testing.T) {
	config := testConfig(t)
	cert, ca := testTLS(t)
	address, user := serveTestIMAP(t, config.IMAP, cert, imap.CapSet{imap.CapIMAP4rev1: {}}, nil)
	config.IMAP.Address, config.IMAP.CAFile = address, ca
	appendRaw := func(raw string) string {
		t.Helper()
		data, err := user.Append("INBOX", strings.NewReader(raw), &imap.AppendOptions{Time: time.Now()})
		if err != nil {
			t.Fatal(err)
		}
		return emailID(mailboxID(config.AccountID, "INBOX"), data.UIDValidity, data.UID)
	}
	id := appendRaw(strings.Join([]string{
		"sUbJeCt: First", "Subject: =?UTF-8?Q?Re=CC=81union?=", "\t=?UTF-8?Q?_notes?=", "Date: 22 Nov 2026 12:00:00 +0200",
		`To: first@example.test, "A, B" <second@example.test>, =?utf-8?Q?=C3=89quipe?=: member@example.test;, Empty:;, last@example.test`,
		"Message-ID: <test@example.test>", "References: <first@example.test>(comment)<second@example.test>",
		"List-Post: (posting) <mailto:list@example.test>, <https://example.test/forum>",
		"X-Local-Date: invalid date", "X-Local-Date: 22 Nov 2026 10:00:00 +0000", "Content-Type: multipart/mixed; boundary=test",
		"", "--test", "Content-Type: text/plain", "X-Part: =?utf-8?Q?P=C3=A4iv=C3=A4?=", "", "Plain body", "--test--", "",
	}, "\r\n"))
	large := appendRaw("Subject: Large header test\r\nX-Only: bounded\r\n\r\n" + strings.Repeat("over limit\r\n", maxRaw/10+1))
	g, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	call := func(method string, args object) (string, object) {
		t.Helper()
		args["accountId"] = config.AccountID
		result := gatewayCalls(t, g, config.Token, [3]any{method, args, "headers"})[0]
		return result.Name, result.Args
	}
	props := []string{"subject", "sentAt", "references", "to", "header:sUbJeCt:asText:all", "header:SUBJECT:asRaw", "header:Date:asDate",
		"header:To:asGroupedAddresses", "header:List-POST:asURLs", "header:References:asMessageIds", "header:X-Local-Date:asDate:all",
		"header:X-Absent", "header:X-Absent:all", "bodyStructure", "textBody"}
	bodyProps := []string{"partId", "header:Content-Type", "header:X-Part:asText"}
	name, result := call("Email/get", object{"ids": []string{id}, "properties": props, "bodyProperties": bodyProps})
	if name != "Email/get" || len(result["list"].([]any)) != 1 {
		t.Fatalf("Email/get: %s %v", name, result)
	}
	item := result["list"].([]any)[0].(map[string]any)
	dates := []any{nil, "2026-11-22T10:00:00Z"}
	if item["subject"] != "Réunion notes" || item["sentAt"] != "2026-11-22T12:00:00+02:00" || item["sentAt"] != item["header:Date:asDate"] ||
		!reflect.DeepEqual(item["header:sUbJeCt:asText:all"], []any{"First", "Réunion notes"}) ||
		item["header:SUBJECT:asRaw"] != " =?UTF-8?Q?Re=CC=81union?=\r\n\t=?UTF-8?Q?_notes?=" ||
		item["header:X-Absent"] != nil || !reflect.DeepEqual(item["header:X-Absent:all"], []any{}) ||
		!reflect.DeepEqual(item["header:List-POST:asURLs"], []any{"mailto:list@example.test", "https://example.test/forum"}) ||
		!reflect.DeepEqual(item["references"], []any{"first@example.test", "second@example.test"}) ||
		!reflect.DeepEqual(item["references"], item["header:References:asMessageIds"]) || !reflect.DeepEqual(item["header:X-Local-Date:asDate:all"], dates) {
		t.Fatalf("typed response: %v", item)
	}
	groups := item["header:To:asGroupedAddresses"].([]any)
	if len(groups) != 4 || groups[0].(map[string]any)["name"] != nil || groups[1].(map[string]any)["name"] != "Équipe" ||
		groups[2].(map[string]any)["name"] != "Empty" || len(groups[2].(map[string]any)["addresses"].([]any)) != 0 ||
		len(item["to"].([]any)) != 4 || item["to"].([]any)[1].(map[string]any)["name"] != "A, B" {
		t.Fatalf("grouped addresses: %v %v", groups, item["to"])
	}
	child := item["bodyStructure"].(map[string]any)["subParts"].([]any)[0].(map[string]any)
	if child["header:X-Part:asText"] != "Päivä" || !reflect.DeepEqual(child, item["textBody"].([]any)[0]) {
		t.Fatalf("body part header projections: %v", item)
	}
	blob := "b-" + id[2:]
	name, result = call("Email/parse", object{"blobIds": []string{blob}, "properties": props, "bodyProperties": bodyProps})
	delete(item, "id")
	if name != "Email/parse" || !reflect.DeepEqual(result["parsed"].(map[string]any)[blob], item) {
		t.Fatalf("Email/parse and Email/get differ: %s %v", name, result)
	}
	name, result = call("Email/get", object{"ids": []string{large}, "properties": []string{"id", "header:X-Only:asText", "headers"}})
	if name != "Email/get" || result["list"].([]any)[0].(map[string]any)["header:X-Only:asText"] != "bounded" {
		t.Fatalf("header-only read of an oversized body: %s %v", name, result)
	}
	for _, property := range []string{"header::all", "header:Subject:all:asText", "header:Date:asAddresses", "header:X Bad", "header:X-A:asBogus", "header:Received:asText"} {
		for _, method := range []string{"Email/get", "Email/parse"} {
			for _, key := range []string{"properties", "bodyProperties"} {
				args := object{key: []string{property}}
				if method == "Email/get" {
					args["ids"] = []string{}
				} else {
					args["blobIds"] = []string{}
				}
				name, result := call(method, args)
				if name != "error" || result["type"] != "invalidArguments" {
					t.Fatalf("%s invalid %s selector %q: %s %v", method, key, property, name, result)
				}
			}
		}
	}
}

func TestHeaderSyntaxAndFailureCases(t *testing.T) {
	if out := headerTextForm("First a=?utf-8?Q?opaque?= =?utf-8?Q?adjacent?=b =?x-unknown?Q?missing?= =?utf-8?Q?with=09control?="); out != "First a=?utf-8?Q?opaque?= =?utf-8?Q?adjacent?=b �withcontrol" {
		t.Fatalf("encoded word placement or replacement: %q", out)
	}
	for _, test := range []struct{ input, form string }{
		{"<ftp://site.example/>", "asMessageIds"}, {"<Bad address>", "asMessageIds"}, {"NO", "asURLs"},
		{"<relative/path>", "asURLs"}, {"<https://bad.example/%zz>", "asURLs"}, {"<https://a.example/>,", "asURLs"},
		{"<https://a.example/> (unterminated", "asURLs"},
	} {
		if got := parseHeaderForm(test.input, test.form); !reflect.DeepEqual(got, []string(nil)) {
			t.Fatalf("malformed header %q %s produced %v", test.input, test.form, got)
		}
	}
	if got := parseHeaderAngles(`(outer (inner \))) <https://a.example/f olded>, <mailto:person@example.test>`, true); !reflect.DeepEqual(got, []string{"https://a.example/folded", "mailto:person@example.test"}) {
		t.Fatalf("RFC2369 whitespace and comments: %v", got)
	}
	groups := parseHeaderAddressGroups(`"Quoted\" Label": "A\" B" <first@example.test>, malformed, escaped@example.test (name, comment); key@[127.0.0.1], (unfinished`)
	if len(groups) != 2 || len(groups[0].Addresses) != 2 || len(groups[1].Addresses) != 1 {
		t.Fatalf("best-effort address groups: %#v", groups)
	}
	partial := parseHeaderAddressGroups("Unfinished: =?utf-8?Q?=09Name?= <valid@example.test>")
	if len(partial) != 1 || len(partial[0].Addresses) != 1 || partial[0].Addresses[0].Name == nil || *partial[0].Addresses[0].Name != "Name" {
		t.Fatalf("invalid group closing marker or encoded control broke fallback: %#v", partial)
	}
	if addresses(mail.Header{}, "From") != nil {
		t.Fatal("strict SMTP address check accepted a missing From header")
	}
	config := testConfig(t)
	cert, ca := testTLS(t)
	endpoint, user := serveTestIMAP(t, config.IMAP, cert, imap.CapSet{imap.CapIMAP4rev1: {}}, func(session imapserver.Session) imapserver.Session {
		return imapFaultSession{Session: session, fault: "missing-search-headers"}
	})
	config.IMAP.Address, config.IMAP.CAFile = endpoint, ca
	msg, err := user.Append("INBOX", strings.NewReader("Subject: Fixture\r\n\r\nBody\r\n"), &imap.AppendOptions{Time: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	g, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	result := gatewayCalls(t, g, config.Token, [3]any{"Email/get", object{"accountId": config.AccountID, "ids": []string{"missing"}, "properties": []string{"header:X-Only"}}, "missing"})[0]
	if result.Name != "Email/get" || !reflect.DeepEqual(result.Args["notFound"], []any{"missing"}) {
		t.Fatalf("header projection for missing Email: %v", result)
	}
	id := emailID(mailboxID(config.AccountID, "INBOX"), msg.UIDValidity, msg.UID)
	result = gatewayCalls(t, g, config.Token, [3]any{"Email/get", object{"accountId": config.AccountID, "ids": []string{id}, "properties": []string{"header:Subject"}}, "failure"})[0]
	if result.Name != "error" || result.Args["type"] != "serverFail" {
		t.Fatalf("missing IMAP header literal: %v", result)
	}
}
