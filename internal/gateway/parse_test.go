package gateway

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"
)

const attachedFixture = "From: lähettäjä@example.test\r\nSubject: Attached message\r\nContent-Type: multipart/mixed; boundary=inner\r\n\r\n" +
	"--inner\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nViesti\r\n" +
	"--inner\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n" +
	"Content-Disposition: attachment; filename=test.bin\r\n\r\nAP8QgA==\r\n--inner--\r\n"

func enclosedFixture(contents string) string {
	return "From: sender@example.test\r\nSubject: Outer\r\nContent-Type: message/rfc822\r\n\r\n" + contents
}

func uploadFixture(t *testing.T, g *Gateway, token, raw string) string {
	t.Helper()
	response := uploadRequest(g, token, "message/rfc822", strings.NewReader(raw))
	var reply struct {
		BlobID string `json:"blobId"`
	}
	if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &reply) != nil || reply.BlobID == "" {
		t.Fatalf("upload failed: %v", response.Body)
	}
	return reply.BlobID
}

func TestEmailParseNestedMime(t *testing.T) {
	config := testConfig(t)
	cert, ca := testTLS(t)
	config.IMAP.CAFile = ca
	config.IMAP.Address, _ = serveTestIMAP(t, config.IMAP, cert, imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapUIDPlus: {}}, nil)
	g, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	blob := uploadFixture(t, g, config.Token, enclosedFixture(attachedFixture))
	invalid := uploadFixture(t, g, config.Token, "not an email")
	missing := "u-" + strings.Repeat("z", 43)
	if missing == blob {
		t.Fatal("fixture collision")
	}
	options := func(ids ...string) object { return object{"accountId": config.AccountID, "blobIds": ids} }
	response := gatewayCalls(t, g, config.Token,
		[3]any{"Email/parse", options(blob, blob, "bad", invalid, missing), "parse"},
	)[0]
	if response.Name != "Email/parse" || len(response.Args["notFound"].([]any)) != 2 ||
		response.Args["notParsable"].([]any)[0] != invalid ||
		len(response.Args["parsed"].(map[string]any)) != 1 {
		t.Fatalf("unexpected parse result: %v", response)
	}
	outer := response.Args["parsed"].(map[string]any)[blob].(map[string]any)
	if _, present := outer["id"]; present || outer["subject"] != "Outer" {
		t.Fatal("unexpected default projection")
	}
	uploadPart := outer["attachments"].([]any)[0].(map[string]any)["blobId"].(string)
	if !strings.HasPrefix(uploadPart, "q-") {
		t.Fatalf("unexpected uploaded part ID: %s", uploadPart)
	}
	mailbox := mailboxID(config.AccountID, "INBOX")
	imported := gatewayCalls(t, g, config.Token, [3]any{
		"Email/import", object{"accountId": config.AccountID, "emails": object{"copy": object{
			"blobId": blob, "mailboxIds": object{mailbox: true},
		}}}, "import",
	})[0]
	imapBlob := imported.Args["created"].(map[string]any)["copy"].(map[string]any)["blobId"].(string)
	for _, parent := range []string{uploadPart, partBlobID(imapBlob, "1")} {
		args := options(parent)
		args["properties"] = []string{"id", "mailboxIds", "keywords", "receivedAt", "threadId", "blobId", "size", "from", "bodyValues", "attachments"}
		args["fetchTextBodyValues"] = true
		result := gatewayCalls(t, g, config.Token, [3]any{"Email/parse", args, "parse"})[0]
		if result.Name != "Email/parse" || result.Args["notParsable"] != nil || result.Args["notFound"] != nil {
			t.Fatalf("nested parse failed: %v", result)
		}
		email := result.Args["parsed"].(map[string]any)[parent].(map[string]any)
		for _, property := range []string{"id", "mailboxIds", "keywords", "receivedAt", "threadId"} {
			if value, has := email[property]; !has || value != nil {
				t.Fatalf("parsed metadata %s was %v", property, value)
			}
		}
		if email["blobId"] != parent || email["from"].([]any)[0].(map[string]any)["email"] != "lähettäjä@example.test" ||
			email["bodyValues"].(map[string]any)["1_1"].(map[string]any)["value"] != "Viesti" {
			t.Fatalf("incorrect parsed contents: %v", email)
		}
		part := email["attachments"].([]any)[0].(map[string]any)["blobId"].(string)
		download := gatewayRequest(g, http.MethodGet, "/download/"+config.AccountID+"/"+part+"/test.bin", config.Token, nil)
		if download.Code != http.StatusOK || download.Body.String() != "\x00\xff\x10\x80" {
			t.Fatalf("nested attachment download failed: HTTP %d, bytes %x", download.Code, download.Body.Bytes())
		}
	}
	deep := attachedFixture
	for range maxNestedBlobParts {
		deep = enclosedFixture(deep)
	}
	deepID := uploadFixture(t, g, config.Token, deep)
	for range maxNestedBlobParts {
		deepID = partBlobID(deepID, "1")
	}
	if result := gatewayCalls(t, g, config.Token, [3]any{"Email/parse", options(deepID), "deep"})[0]; result.Args["notParsable"].([]any)[0] != deepID {
		t.Fatalf("nesting limit was ignored: %v", result)
	}
}

func TestParseValidationAndBlobBudget(t *testing.T) {
	config := testConfig(t)
	g, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	blob := uploadFixture(t, g, config.Token, attachedFixture)
	id := "q-" + blob[2:]
	for _, bad := range []string{"bad", blob + "-1", id, id + "-2", id + strings.Repeat("-1", maxNestedBlobParts+1)} {
		if _, valid := locateBlob(bad); valid {
			t.Fatalf("accepted invalid locator %q", bad)
		}
	}
	for _, test := range []struct {
		args object
		want string
	}{
		{object{"ids": []string{}}, "invalidArguments"},
		{object{"blobIds": []string{blob}, "ids": []string{}}, "invalidArguments"},
		{object{"blobIds": []string{blob}, "maxBodyValueBytes": -1}, "invalidArguments"},
		{object{"blobIds": make([]string, maxGet+1)}, "requestTooLarge"},
	} {
		test.args["accountId"] = config.AccountID
		result := gatewayCalls(t, g, config.Token, [3]any{"Email/parse", test.args, "parse"})[0]
		if result.Name != "error" || result.Args["type"] != test.want {
			t.Fatalf("unexpected method response: %v", result)
		}
	}
	op := operation{g: g, rawBytes: 12 * maxRaw}
	if _, failure := op.parseEmails(rawArgs(t, object{"blobIds": []string{blob}})); failure != "requestTooLarge" {
		t.Fatalf("did not enforce cumulative blob size: %q", failure)
	}
}

func TestPartDownloadOctetsAndLegacyIdentifier(t *testing.T) {
	config := testConfig(t)
	cert, ca := testTLS(t)
	config.IMAP.CAFile = ca
	config.IMAP.Address, _ = serveTestIMAP(t, config.IMAP, cert, imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapUIDPlus: {}}, nil)
	g, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	blob := uploadFixture(t, g, config.Token, "Subject: Encoded body\r\nContent-Type: text/plain; charset=iso-8859-1\r\n"+
		"Content-Transfer-Encoding: quoted-printable\r\n\r\n=E9")
	imported := gatewayCalls(t, g, config.Token,
		[3]any{"Email/import", object{"accountId": config.AccountID, "emails": object{"email": object{
			"blobId": blob, "mailboxIds": object{mailboxID(config.AccountID, "INBOX"): true},
		}}}, "import"},
		[3]any{"Email/get", object{"accountId": config.AccountID, "ids": []string{"#email"}, "fetchTextBodyValues": true}, "get"},
	)
	record := imported[1].Args["list"].([]any)[0].(map[string]any)
	part := record["textBody"].([]any)[0].(map[string]any)
	if part["size"] != float64(1) || record["bodyValues"].(map[string]any)["1"].(map[string]any)["value"] != "é" {
		t.Fatalf("body view does not separate display text from its octet count: %v", record)
	}
	partID := part["blobId"].(string)
	for _, test := range []struct{ id, data string }{
		{partID, "\xe9"},
		{"p-" + partID[2:], "é"},
		{partBlobID(blob, "1"), "\xe9"},
	} {
		file := gatewayRequest(g, http.MethodGet, "/download/"+config.AccountID+"/"+test.id+"/encoded", config.Token, nil)
		if file.Code != http.StatusOK || file.Body.String() != test.data {
			t.Fatalf("blob %s returned HTTP %d and bytes %x", test.id[:2], file.Code, file.Body.Bytes())
		}
	}
}
