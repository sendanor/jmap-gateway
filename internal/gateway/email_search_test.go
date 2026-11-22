package gateway

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
)

func TestEmailQuerySearchMIMEAndHeaders(t *testing.T) {
	config := testConfig(t)
	cert, ca := testTLS(t)
	address, user := serveTestIMAP(t, config.IMAP, cert, imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapUIDPlus: {}}, nil)
	config.IMAP.Address, config.IMAP.CAFile = address, ca
	inbox := mailboxID(config.AccountID, "INBOX")
	appendMessage := func(raw string) string {
		t.Helper()
		msg, err := user.Append("INBOX", strings.NewReader(raw), &imap.AppendOptions{Time: time.Now()})
		if err != nil {
			t.Fatal(err)
		}
		return emailID(inbox, msg.UIDValidity, msg.UID)
	}
	message := appendMessage(strings.Join([]string{
		"From: =?UTF-8?Q?L=C3=A9a_Cohen?= <lea@example.test>", "To: Aaron <aaron@example.test>",
		"Cc: carbon@example.test", "Bcc: secret@example.test", "Subject: =?UTF-8?Q?R=C3=A9union_projet?=",
		"X-Label: =?UTF-8?Q?Premi=C3=A8re?=", "X-Label: Status Seven", "Empty-Label:",
		"Content-Type: multipart/mixed; boundary=outer", "", "--outer", "Content-Type: text/html; charset=utf-8", "",
		`<html><head><title>secretmeta</title></head><body><p>One fran<b>çais</b> &amp; tea.</p>`,
		`<script title="scriptmetadata">unseenjavascript()</script><style>invisiblestyle</style><!-- hiddencomment -->`,
		`<img src="notindexed.example" alt="Orange flowers" title="Field notes">`,
		`<div>the wildcat runs quickly; and the cat runs.</div></body></html>`,
		"--outer", "Content-Type: text/plain; charset=iso-8859-1", "Content-Transfer-Encoding: quoted-printable",
		"Content-Disposition: attachment; filename=notes.txt", "", "Cr=E8me br=FBl=E9e and jalape=F1o.",
		"--outer", "Content-Type: application/octet-stream", "Content-Disposition: attachment; filename=archive.bin",
		"", "binaryspecialword", "--outer--", "",
	}, "\r\n"))
	plain := appendMessage("Subject: Simple text\r\nX-Unrelated: hidden\r\n\r\nA cup of coffee and a wildcat runs.\r\n")
	g, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	call := func(method string, args object) (string, object) {
		t.Helper()
		args["accountId"] = config.AccountID
		response := gatewayCalls(t, g, config.Token, [3]any{method, args, "q"})[0]
		return response.Name, response.Args
	}
	query := func(filter object, expected ...string) object {
		t.Helper()
		name, result := call("Email/query", object{"filter": filter})
		want := make([]any, 0, len(expected))
		for _, id := range expected {
			want = append(want, id)
		}
		if name != "Email/query" || !reflect.DeepEqual(result["ids"], want) {
			t.Fatalf("filter %v returned %s %v, want %v", filter, name, result, want)
		}
		return result
	}
	query(object{"from": "LÉA cohen", "to": "Aaron", "cc": "carbon", "bcc": "secret", "subject": "réunion"}, message)
	query(object{"header": []string{"empty-label"}}, message)
	query(object{"header": []string{"x-label", `"status seven"`}}, message)
	query(object{"header": []string{"x-label", "PREMIÈRE"}}, message)
	query(object{"header": []string{"x-absent"}})
	query(object{"header": []string{"x-label", `"seven status"`}})
	query(object{"text": `"réunion projet" lea@example.test orange secret jalapeño`, "body": `"français & tea"`, "subject": "projet"}, message)
	query(object{"body": `"crème brûlée" "orange flowers" "field notes"`}, message)
	query(object{"body": `"cat runs"`}, message)
	for _, term := range []string{"secretmeta", "unseenjavascript", "scriptmetadata", "invisiblestyle", "hiddencomment", "notindexed.example", "binaryspecialword"} {
		query(object{"body": term})
	}
	query(object{"hasAttachment": true}, message)
	query(object{"hasAttachment": false, "body": "coffee"}, plain)
	for _, filter := range []object{
		{"subject": nil}, {"hasAttachment": nil}, {"header": []any{}}, {"header": []any{nil}},
		{"header": []string{"From:"}}, {"header": []any{"From", nil}}, {"header": []string{"From", "x", "y"}},
	} {
		name, result := call("Email/query", object{"filter": filter})
		if name != "error" || result["type"] != "invalidArguments" {
			t.Fatalf("invalid filter %v returned %s %v", filter, name, result)
		}
	}
	filter := object{"body": "coffee"}
	before := query(filter, plain)
	later := appendMessage("Subject: More\r\n\r\nMore coffee.\r\n")
	name, delta := call("Email/queryChanges", object{"filter": filter, "sinceQueryState": before["queryState"]})
	if name != "Email/queryChanges" || !reflect.DeepEqual(delta["added"], []any{map[string]any{"id": later, "index": float64(0)}}) {
		t.Fatalf("search query changes: %s %v", name, delta)
	}
	// Header-only search uses a separately bounded IMAP section, even when
	// the body exceeds the maximum raw message size.
	large := appendMessage("Subject: Large transport\r\n\r\n" + strings.Repeat("body line\r\n", maxRaw/11+1))
	query(object{"subject": "large transport"}, large)
	query(object{"body": "coffee", "maxSize": int64(maxRaw)}, later, plain)
	name, result := call("Email/query", object{"filter": object{"body": "coffee"}})
	if name != "error" || result["type"] != "serverFail" {
		t.Fatalf("search against an oversized candidate returned a partial result: %s %v", name, result)
	}
	name, result = call("Email/get", object{"ids": []string{message}, "properties": []string{"keywords"}})
	if name != "Email/get" || len(result["list"].([]any)[0].(map[string]any)["keywords"].(map[string]any)) != 0 {
		t.Fatalf("search marked an IMAP message read: %s %v", name, result)
	}
}

func TestEmailQuerySearchFailuresAndTerms(t *testing.T) {
	for _, test := range []struct {
		query, value string
		want         bool
	}{
		{` "this \"quote\""  'another phrase' `, `another phrase and this "quote".`, true},
		{`"cat"`, "wildcat catatonic", false},
		{`"cat"`, "wildcat cat", true},
		{`"" word`, "word", true},
		{`"open quote`, `an "open quote`, true},
	} {
		if got := matchesSearch(searchTerms(test.query), []string{normalizeSearch(test.value)}); got != test.want {
			t.Fatalf("%q against %q returned %v", test.query, test.value, got)
		}
	}
	cert, ca := testTLS(t)
	for _, test := range []struct {
		fault, raw, property, want string
	}{
		{"body-gone", "Subject: fixture\r\n\r\nhello", "body", "serverUnavailable"},
		{"", "Subject: bad\r\nContent-Type: multipart/mixed; boundary=missing\r\n\r\nno parts", "body", "serverFail"},
		{"invalid-search-headers", "Subject: fixture\r\n\r\nhello", "subject", "serverFail"},
		{"missing-search-headers", "Subject: fixture\r\n\r\nhello", "subject", "serverFail"},
		{"", "Subject: fixture\r\n\r\nhello", "subject", "requestTooLarge"},
	} {
		t.Run(test.fault+test.want, func(t *testing.T) {
			config := testConfig(t)
			address, user := serveTestIMAP(t, config.IMAP, cert, imap.CapSet{imap.CapIMAP4rev1: {}}, func(session imapserver.Session) imapserver.Session {
				return imapFaultSession{Session: session, fault: test.fault}
			})
			config.IMAP.Address, config.IMAP.CAFile = address, ca
			if _, err := user.Append("INBOX", strings.NewReader(test.raw), &imap.AppendOptions{Time: time.Now()}); err != nil {
				t.Fatal(err)
			}
			g, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			defer g.Close()
			op := operation{g: g, ctx: context.Background()}
			defer func() {
				if op.closeIMAP != nil {
					op.closeIMAP()
				}
			}()
			if test.want == "requestTooLarge" {
				op.rawBytes = 12 * maxRaw
			}
			if _, failure := op.query(rawArgs(t, object{"filter": object{test.property: "fixture"}})); failure != test.want {
				t.Fatalf("search returned %q, want %q", failure, test.want)
			}
		})
	}
}
