package gateway

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
)

func TestImportUploadedMessage(t *testing.T) {
	cert, ca := testTLS(t)
	g := testGatewayForIMAP(t, cert, ca, "", imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapUIDPlus: {}})
	c := g.config
	const token = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	inbox := mailboxID(c.AccountID, "INBOX")
	drafts := mailboxID(c.AccountID, "Drafts")
	raw := "From: lähettäjä@example.test\r\nTo: recipient@example.test\r\nSubject: Tuonti\r\n" +
		"Received: from relay.example.test; Mon, 02 Mar 2026 15:06:00 +0200\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n\r\nViesti\r\n"
	upload := uploadRequest(g, token, "message/rfc822", strings.NewReader(raw))
	var blob object
	if upload.Code != http.StatusCreated || json.Unmarshal(upload.Body.Bytes(), &blob) != nil {
		t.Fatal("unable to upload import message")
	}
	id := blob["blobId"].(string)
	options := object{
		"accountId": c.AccountID,
		"emails": object{
			"inbox":   object{"blobId": id, "mailboxIds": object{inbox: true}, "keywords": object{"$seen": true, "$answered": true, "$flagged": true, "custom": true}},
			"draft":   object{"blobId": id, "mailboxIds": object{drafts: true}, "keywords": object{"$draft": true}, "receivedAt": "2026-03-02T09:30:00Z"},
			"invalid": object{"blobId": id, "mailboxIds": object{inbox: true, drafts: true}},
		},
	}
	calls := gatewayCalls(t, g, token,
		[3]any{"Email/import", options, "import"},
		[3]any{"Email/get", object{"accountId": c.AccountID, "ids": []string{"#inbox", "#draft"}, "fetchTextBodyValues": true}, "get"},
	)
	result := calls[0]
	if result.Name != "Email/import" || result.Args["oldState"] == result.Args["newState"] {
		t.Fatalf("import did not update the state: %v", result)
	}
	created := result.Args["created"].(map[string]any)
	inboxObject := created["inbox"].(map[string]any)
	draftObject := created["draft"].(map[string]any)
	if inboxObject["id"] == draftObject["id"] || inboxObject["size"] != float64(len(raw)) || inboxObject["blobId"] == nil || inboxObject["threadId"] == nil {
		t.Fatalf("import did not return independent metadata: %v", created)
	}
	if result.Args["notCreated"].(map[string]any)["invalid"].(map[string]any)["type"] != "invalidProperties" {
		t.Fatal("multi-mailbox import should report the current limit")
	}
	list := calls[1].Args["list"].([]any)
	if len(list) != 2 || calls[1].Args["state"] != result.Args["newState"] {
		t.Fatalf("import results not visible to same request: %v", calls[1])
	}
	msg := list[0].(map[string]any)
	flags := msg["keywords"].(map[string]any)
	from := msg["from"].([]any)[0].(map[string]any)
	if msg["receivedAt"] != "2026-03-02T13:06:00Z" || from["email"] != "lähettäjä@example.test" ||
		flags["$seen"] != true || flags["$answered"] != true || flags["$flagged"] != true || flags["custom"] != true {
		t.Fatalf("wrong inbox import values: %v", msg)
	}
	draft := list[1].(map[string]any)
	if draft["receivedAt"] != "2026-03-02T09:30:00Z" || draft["keywords"].(map[string]any)["$draft"] != true {
		t.Fatalf("wrong draft import values: %v", draft)
	}
	original := gatewayRequest(g, http.MethodGet, "/download/"+c.AccountID+"/"+inboxObject["blobId"].(string)+"/message.eml", token, nil)
	if original.Code != http.StatusOK || original.Body.String() != raw {
		t.Fatal("IMAP import changed the message bytes")
	}
	empty := gatewayCalls(t, g, token, [3]any{"Email/import", object{"accountId": c.AccountID, "emails": object{}}, "empty"})[0]
	if empty.Name != "Email/import" || empty.Args["oldState"] != empty.Args["newState"] ||
		empty.Args["created"] != nil || empty.Args["notCreated"] != nil {
		t.Fatalf("empty import returned %v", empty)
	}
}

func TestCreationIDReuseAcrossMailboxAndImport(t *testing.T) {
	cert, ca := testTLS(t)
	g := testGatewayForIMAP(t, cert, ca, "", imap.CapSet{
		imap.CapIMAP4rev1: {}, imap.CapUIDPlus: {},
	})
	account := g.config.AccountID
	const token = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	raw := "From: sender@example.test\r\nSubject: Creation references\r\n\r\nImported\r\n"
	upload := uploadRequest(g, token, "message/rfc822", strings.NewReader(raw))
	var blob object
	if upload.Code != http.StatusCreated || json.Unmarshal(upload.Body.Bytes(), &blob) != nil {
		t.Fatal("unable to upload import message")
	}

	calls := gatewayCalls(t, g, token,
		[3]any{"Mailbox/set", object{"accountId": account, "create": object{
			"reuse": object{"name": "First"},
		}}, "first"},
		[3]any{"Mailbox/set", object{"accountId": account, "create": object{
			"reuse": object{"name": "Archive"}, "child": object{"name": "Child", "parentId": "#reuse"},
		}}, "archive"},
		[3]any{"Email/import", object{"accountId": account, "emails": object{
			"reuse": object{"blobId": blob["blobId"], "mailboxIds": object{"#reuse": true}},
		}}, "import"},
		[3]any{"Email/get", object{"accountId": account, "ids": []string{"#reuse"}}, "read"},
	)
	created := func(index int, key string) map[string]any {
		t.Helper()
		objects, _ := calls[index].Args["created"].(map[string]any)
		record, _ := objects[key].(map[string]any)
		if record["id"] == nil {
			t.Fatalf("method %d did not create %q: %v", index, key, calls[index])
		}
		return record
	}
	first, archive := created(0, "reuse")["id"], created(1, "reuse")["id"]
	if first == archive || created(1, "child")["parentId"] != archive {
		t.Fatal("child did not use the newly created parent")
	}
	email := created(2, "reuse")["id"]
	list, _ := calls[3].Args["list"].([]any)
	if len(list) != 1 {
		t.Fatalf("imported message was not resolved: %v", calls[3])
	}
	message := list[0].(map[string]any)
	if message["id"] != email || message["mailboxIds"].(map[string]any)[archive.(string)] != true {
		t.Fatalf("incorrect imported message or mailbox: %v", message)
	}
}

func TestImportValidation(t *testing.T) {
	cert, ca := testTLS(t)
	g := testGatewayForIMAP(t, cert, ca, "read-only", imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapUIDPlus: {}})
	account := g.config.AccountID
	inbox := mailboxID(account, "INBOX")
	const token = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	upload := func(raw string) string {
		t.Helper()
		added := uploadRequest(g, token, "message/rfc822", strings.NewReader(raw))
		var data object
		if added.Code != http.StatusCreated || json.Unmarshal(added.Body.Bytes(), &data) != nil {
			t.Fatal("fixture upload failed")
		}
		return data["blobId"].(string)
	}
	valid := upload("Subject: test\r\n\r\ntext\r\n")
	notEmail := upload("\x00\r\n\r\n")
	failedRead := "u-" + strings.Repeat("x", 43)
	if err := os.Mkdir(filepath.Join(g.uploads.dir, uploadFilePrefix+failedRead), 0700); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name           string
		input          any
		want, property string
	}{
		{"malformed", true, "invalidProperties", ""},
		{"blob id", object{"blobId": "invalid", "mailboxIds": object{inbox: true}}, "invalidProperties", "blobId"},
		{"missing blob", object{"blobId": "u-" + strings.Repeat("z", 43), "mailboxIds": object{inbox: true}}, "invalidProperties", "blobId"},
		{"mailbox", object{"blobId": valid, "mailboxIds": object{"foreign": true}}, "invalidProperties", "mailboxIds"},
		{"keywords", object{"blobId": valid, "mailboxIds": object{inbox: true}, "keywords": object{"bad word": true}}, "invalidProperties", "keywords"},
		{"date", object{"blobId": valid, "mailboxIds": object{inbox: true}, "receivedAt": "2026-03-02T09:30:00+00:00"}, "invalidProperties", "receivedAt"},
		{"invalid email", object{"blobId": notEmail, "mailboxIds": object{inbox: true}}, "invalidEmail", ""},
		{"read failed", object{"blobId": failedRead, "mailboxIds": object{inbox: true}}, "serverUnavailable", ""},
		{"read only mailbox", object{"blobId": valid, "mailboxIds": object{inbox: true}}, "forbidden", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := gatewayCalls(t, g, token, [3]any{"Email/import", object{"accountId": account, "emails": object{"fail": test.input}}, "request"})[0]
			if result.Name != "Email/import" || result.Args["oldState"] != result.Args["newState"] {
				t.Fatalf("invalid item changed account state: %v", result)
			}
			failure := result.Args["notCreated"].(map[string]any)["fail"].(map[string]any)
			if failure["type"] != test.want || test.property != "" && failure["properties"].([]any)[0] != test.property {
				t.Fatalf("unexpected error: %v", failure)
			}
		})
	}
	aboveLimit := make(object)
	for i := range maxSet + 1 {
		aboveLimit[string(rune('a'+i))] = object{}
	}
	for _, test := range []struct {
		args     object
		expected string
	}{
		{object{"accountId": account}, "invalidArguments"},
		{object{"accountId": account, "emails": aboveLimit}, "requestTooLarge"},
		{object{"accountId": account, "emails": object{"invalid!": object{}}}, "invalidArguments"},
		{object{"accountId": account, "emails": object{}, "ifInState": "stale"}, "stateMismatch"},
	} {
		result := gatewayCalls(t, g, token, [3]any{"Email/import", test.args, "request"})[0]
		if result.Name != "error" || result.Args["type"] != test.expected {
			t.Fatalf("invalid import call returned %v", result)
		}
	}
	op := operation{g: g, snapshotFailure: "serverUnavailable"}
	if _, failure := op.importEmails(rawArgs(t, object{"accountId": account, "emails": object{}})); failure != "serverUnavailable" {
		t.Fatalf("unexpected import error for unavailable IMAP: %s", failure)
	}
	op = operation{g: g, snapshot: &snapshot{boxes: []*box{{ID: inbox}}, emails: make(map[string]*emailMeta)}}
	for i := range maxMessages {
		op.snapshot.emails[emailID(inbox, 1, imap.UID(i+1))] = &emailMeta{}
	}
	input, err := json.Marshal(object{"blobId": valid, "mailboxIds": object{inbox: true}})
	if err != nil {
		t.Fatal(err)
	}
	if _, failure := op.importEmail(input); failure["type"] != "overQuota" {
		t.Fatalf("import above quota returned %v", failure)
	}
}

func TestImportDateFallback(t *testing.T) {
	now := time.Date(2026, 3, 2, 15, 0, 0, 0, time.FixedZone("fixture", 7200))
	for _, test := range []struct{ received, want string }{
		{"without a semicolon", "2026-03-02T13:00:00Z"},
		{"from nowhere; not a date", "2026-03-02T13:00:00Z"},
		{"from relay; Mon, 02 Mar 2026 15:06:00 +0200", "2026-03-02T13:06:00Z"},
	} {
		got, ok := importDate(map[string][]string{"Received": {test.received}}, nil, now)
		if !ok || got.Format(time.RFC3339) != test.want {
			t.Fatalf("invalid Received fallback: %q returned %s", test.received, got)
		}
	}
}

func TestMailboxUnreadExcludesDrafts(t *testing.T) {
	cert, ca := testTLS(t)
	g := testGatewayForIMAP(t, cert, ca, "", imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapUIDPlus: {}})
	account := g.config.AccountID
	inbox := mailboxID(account, "INBOX")
	const token = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	blob := uploadFixture(t, g, token, "From: user@example.test\r\nSubject: Counts\r\n\r\nContent\r\n")
	imported := gatewayCalls(t, g, token, [3]any{
		"Email/import", object{"accountId": account, "emails": object{
			"normal": object{"blobId": blob, "mailboxIds": object{inbox: true}},
			"draft":  object{"blobId": blob, "mailboxIds": object{inbox: true}, "keywords": object{"$draft": true}},
		}}, "import",
	})[0]
	created := imported.Args["created"].(map[string]any)
	normal := created["normal"].(map[string]any)["id"].(string)
	draft := created["draft"].(map[string]any)["id"].(string)
	for _, test := range []struct {
		id     string
		seen   any
		unread float64
	}{
		{draft, true, 1}, {draft, nil, 1}, {normal, true, 0}, {normal, nil, 1},
	} {
		methods := gatewayCalls(t, g, token,
			[3]any{"Email/set", object{"accountId": account, "update": object{test.id: object{"keywords/$seen": test.seen}}}, "update"},
			[3]any{"Mailbox/get", object{"accountId": account, "ids": []string{inbox}}, "counts"},
		)
		if methods[0].Args["updated"] == nil || len(methods[1].Args["list"].([]any)) != 1 {
			t.Fatalf("unexpected mailbox response: %v", methods)
		}
		counts := methods[1].Args["list"].([]any)[0].(map[string]any)
		if counts["totalEmails"] != float64(2) || counts["unreadEmails"] != test.unread {
			t.Fatalf("unexpected unread or total count: %v", counts)
		}
	}
}
