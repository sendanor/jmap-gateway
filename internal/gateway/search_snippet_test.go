package gateway

import (
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
)

func TestSearchSnippetGet(t *testing.T) {
	config := testConfig(t)
	cert, ca := testTLS(t)
	address, user := serveTestIMAP(t, config.IMAP, cert, imap.CapSet{imap.CapIMAP4rev1: {}}, nil)
	config.IMAP.Address, config.IMAP.CAFile = address, ca
	appendMessage := func(msg string) string {
		t.Helper()
		data, err := user.Append("INBOX", strings.NewReader(msg), &imap.AppendOptions{Time: time.Now()})
		if err != nil {
			t.Fatal(err)
		}
		return emailID(mailboxID(config.AccountID, "INBOX"), data.UIDValidity, data.UID)
	}
	first := appendMessage("Subject: =?UTF-8?Q?=C4=B0:_Release?=   & <note> blocked\r\nContent-Type: text/html; charset=utf-8\r\n\r\n" +
		"<head><title>hidden</title></head><p>Release &amp; notes &lt;safe&gt;</p><script>hidden</script>")
	second := appendMessage("Subject: Other =?x-unknown?Q?opaque?=\r\n\r\nDifferent\r\n")
	tooLarge := appendMessage("Subject: Release\r\n\r\n" + strings.Repeat("Long message\r\n", maxRaw/14+1))
	g, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	call := func(method string, args object) (string, object) {
		t.Helper()
		args["accountId"] = config.AccountID
		result := gatewayCalls(t, g, config.Token, [3]any{method, args, "snippet"})[0]
		return result.Name, result.Args
	}
	filter := object{"operator": "OR", "conditions": []object{
		{"header": []string{"subject", "note"}, "body": `"release & notes"`},
		{"text": "i release"},
		{"operator": "NOT", "conditions": []object{{"text": "blocked hidden"}}},
	}}
	name, result := call("SearchSnippet/get", object{"filter": filter, "emailIds": []string{first, second, "missing", first, tooLarge}})
	if name != "SearchSnippet/get" || result["accountId"] != config.AccountID || len(result) != 3 ||
		!reflect.DeepEqual(result["notFound"], []any{"missing"}) {
		t.Fatalf("snippet response: %s %v", name, result)
	}
	list := result["list"].([]any)
	want := []any{
		map[string]any{"emailId": first, "subject": "<mark>İ</mark>: <mark>Release</mark>   &amp; &lt;<mark>note</mark>&gt; blocked",
			"preview": "<mark>Release &amp; notes</mark> &lt;safe&gt;"},
		map[string]any{"emailId": second, "subject": nil, "preview": "D<mark>i</mark>fferent"},
		map[string]any{"emailId": tooLarge, "subject": nil, "preview": nil},
	}
	if !reflect.DeepEqual(list, want) {
		t.Fatalf("snippets = %#v, want %#v", list, want)
	}
	name, result = call("SearchSnippet/get", object{"filter": object{"subject": "release"}, "emailIds": []string{tooLarge}})
	if name != "SearchSnippet/get" || result["notFound"] != nil ||
		!reflect.DeepEqual(result["list"], []any{map[string]any{"emailId": tooLarge, "subject": "<mark>Release</mark>", "preview": nil}}) {
		t.Fatalf("header-only snippet for large message: %s %v", name, result)
	}
	name, result = call("SearchSnippet/get", object{"filter": object{"body": "different"}, "emailIds": []string{second}})
	if name != "SearchSnippet/get" || !reflect.DeepEqual(result["list"], []any{map[string]any{"emailId": second, "subject": nil, "preview": "<mark>Different</mark>"}}) {
		t.Fatalf("plain body only: %s %v", name, result)
	}
	name, result = call("SearchSnippet/get", object{"filter": nil, "emailIds": []string{second}})
	if name != "SearchSnippet/get" || !reflect.DeepEqual(result["list"], []any{map[string]any{"emailId": second, "subject": nil, "preview": nil}}) {
		t.Fatalf("null filter: %s %v", name, result)
	}
	name, result = call("SearchSnippet/get", object{"emailIds": []string{}})
	if name != "SearchSnippet/get" || result["notFound"] != nil || len(result["list"].([]any)) != 0 {
		t.Fatalf("empty request: %s %v", name, result)
	}
	for _, check := range []struct {
		args object
		want string
	}{
		{object{}, "invalidArguments"},
		{object{"emailIds": []any{nil}}, "invalidArguments"},
		{object{"emailIds": make([]string, maxGet+1)}, "requestTooLarge"},
		{object{"filter": object{"unknown": "word"}, "emailIds": []string{first}}, "unsupportedFilter"},
	} {
		name, result = call("SearchSnippet/get", check.args)
		if name != "error" || result["type"] != check.want {
			t.Fatalf("invalid snippet call returned %s %v, want %s", name, result, check.want)
		}
	}
	name, result = call("Email/get", object{"ids": []string{first}, "properties": []string{"keywords"}})
	if name != "Email/get" || len(result["list"].([]any)[0].(map[string]any)["keywords"].(map[string]any)) != 0 {
		t.Fatalf("snippet changed IMAP seen flags: %s %v", name, result)
	}
}

func TestSearchSnippetPreviewLimits(t *testing.T) {
	text := strings.Repeat("&& € ", 100) + "First " + strings.Repeat("&", 40) + " Second " + strings.Repeat("<€>", 100)
	preview := highlightSnippet(text, searchTerms("first second"), true)
	if len(preview) > maxSnippetBytes || !utf8.ValidString(preview) ||
		!strings.HasPrefix(preview, "…") || !strings.HasSuffix(preview, "…") ||
		!strings.Contains(preview, "<mark>First</mark>") || strings.Contains(preview, "<mark>Second</mark>") {
		t.Fatalf("preview exceeded its escaped budget or lost its first match: %q (%d bytes)", preview, len(preview))
	}
	if got := highlightSnippet("Re: İ & X\t   Y", searchTerms(`i "x y" x`), false); got != "Re: <mark>İ</mark> &amp; <mark>X\t   Y</mark>" {
		t.Fatalf("subject highlighting changed original whitespace or Unicode offsets: %q", got)
	}
	if got := highlightSnippet(strings.Repeat("&", 100), searchTerms(`"`+strings.Repeat("&", 100)+`"`), true); got != "" {
		t.Fatalf("oversize match produced a partial mark: %q", got)
	}
	if got := highlightSnippet("banana &", searchTerms("ana ana"), false); got != "b<mark>anana</mark> &amp;" {
		t.Fatalf("overlapping and duplicate matches: %q", got)
	}
}

func TestSearchSnippetVanishedMessageAndUpstream(t *testing.T) {
	config := testConfig(t)
	cert, ca := testTLS(t)
	address, user := serveTestIMAP(t, config.IMAP, cert, imap.CapSet{imap.CapIMAP4rev1: {}}, func(session imapserver.Session) imapserver.Session {
		return imapFaultSession{Session: session, fault: "body-gone"}
	})
	config.IMAP.Address, config.IMAP.CAFile = address, ca
	message, err := user.Append("INBOX", strings.NewReader("Subject: Gone\r\n\r\nGone\r\n"), &imap.AppendOptions{Time: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	id := emailID(mailboxID(config.AccountID, "INBOX"), message.UIDValidity, message.UID)
	g, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	args := object{"accountId": config.AccountID, "filter": object{"body": "gone"}, "emailIds": []string{id}}
	result := gatewayCalls(t, g, config.Token, [3]any{"SearchSnippet/get", args, "vanished"})[0]
	if result.Name != "SearchSnippet/get" || !reflect.DeepEqual(result.Args["notFound"], []any{id}) {
		t.Fatalf("message vanishing during read: %v", result)
	}
	closed := listenTCP(t)
	g.config.IMAP.Address = closed.Addr().String()
	_ = closed.Close()
	result = gatewayCalls(t, g, config.Token, [3]any{"SearchSnippet/get", args, "unavailable"})[0]
	if result.Name != "error" || result.Args["type"] != "serverUnavailable" {
		t.Fatalf("unavailable mailbox: %v", result)
	}
}
