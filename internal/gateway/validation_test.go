package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
)

func rawArgs(t *testing.T, args object) rawObject {
	t.Helper()
	data, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	var raw rawObject
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestAPIRequestErrors(t *testing.T) {
	config := testConfig(t)
	gateway, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer gateway.Close()

	for _, test := range []struct {
		name, contentType, body, kind, limit string
		status                               int
	}{
		{"content type", "text/plain", "{}", "notJSON", "", 415},
		{"malformed JSON", "application/json", "{", "notJSON", "", 400},
		{"invalid UTF-8", "application/json", `{"x":"` + string([]byte{255}) + `"}`, "notJSON", "", 400},
		{"wrong-case using", "application/json", `{"Using":[],"methodCalls":[]}`, "notRequest", "", 400},
		{"non-object envelope", "application/json", `[]`, "notRequest", "", 400},
		{"null capability", "application/json", `{"using":[null],"methodCalls":[]}`, "notRequest", "", 400},
		{"null creation IDs", "application/json", `{"using":[],"methodCalls":[],"createdIds":null}`, "notRequest", "", 400},
		{"null call name", "application/json", `{"using":[],"methodCalls":[[null,{},"tag"]]}`, "notRequest", "", 400},
		{"null call tag", "application/json", `{"using":[],"methodCalls":[["Core/echo",{},null]]}`, "notRequest", "", 400},
		{"missing using", "application/json", `{"methodCalls":[]}`, "notRequest", "", 400},
		{"unknown capability", "application/json", `{"using":["unknown"],"methodCalls":[]}`, "unknownCapability", "", 400},
		{"size limit", "application/json", strings.Repeat(" ", maxRequest+1), "limit", "maxSizeRequest", 413},
		{"calls limit", "application/json", `{"using":[],"methodCalls":[` + strings.Repeat("null,", maxCalls) + "null]}", "limit", "maxCallsInRequest", 413},
		{"bad invocation", "application/json", `{"using":[],"methodCalls":[[]]}`, "notRequest", "", 400},
		{"invalid creation id", "application/json", `{"using":[],"methodCalls":[],"createdIds":{"!":"a"}}`, "notRequest", "", 400},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "https://gateway.example/jmap", strings.NewReader(test.body))
			request.Header.Set("Content-Type", test.contentType)
			request.Header.Set("Authorization", "Bearer "+config.Token)
			response := httptest.NewRecorder()
			gateway.ServeHTTP(response, request)
			checkProblem(t, response, test.status, test.kind, test.limit)
		})
	}

	request := httptest.NewRequest(http.MethodPost, "https://gateway.example/jmap", failingReader{})
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+config.Token)
	response := httptest.NewRecorder()
	gateway.ServeHTTP(response, request)
	checkProblem(t, response, 400, "notJSON", "")

	for _, test := range []struct {
		method, path string
		status       int
	}{
		{http.MethodPost, "/.well-known/jmap", 405},
		{http.MethodGet, "/jmap", 405},
		{http.MethodGet, "/upload/" + config.AccountID, 405},
		{http.MethodGet, "/events", 400},
		{http.MethodPost, "/events", 405},
		{http.MethodGet, "/download/bad/path", 404},
		{http.MethodGet, "/download/" + config.AccountID + "/x-" + strings.Repeat("a", 43) + "/file", 404},
		{http.MethodGet, "/unknown", 404},
	} {
		actual := gatewayRequest(gateway, test.method, test.path, config.Token, nil)
		if actual.Code != test.status {
			t.Errorf("%s %s returned %d, want %d", test.method, test.path, actual.Code, test.status)
		}
	}
	plain := httptest.NewRecorder()
	gateway.ServeHTTP(plain, httptest.NewRequest(http.MethodGet, "http://gateway.example/.well-known/jmap", nil))
	if plain.Code != 400 {
		t.Errorf("plaintext status %d, want 400", plain.Code)
	}

	raw := []byte(`{"using":["urn:ietf:params:jmap:core"],"methodCalls":[["Email/get",{},"wrong-capability"],["Core/echo",{"name":"fixture"},"echo"]],"createdIds":{"original":"kept"}}`)
	answer := gatewayRequest(gateway, http.MethodPost, "/jmap", config.Token, raw)
	if answer.Code != 200 || !strings.Contains(answer.Body.String(), `"original":"kept"`) ||
		!strings.Contains(answer.Body.String(), `"type":"unknownMethod"`) {
		t.Fatalf("unexpected mixed API response: %s", answer.Body)
	}
}

func checkProblem(t *testing.T, response *httptest.ResponseRecorder, status int, kind, limit string) {
	t.Helper()
	var data object
	if response.Code != status || json.Unmarshal(response.Body.Bytes(), &data) != nil ||
		data["type"] != "urn:ietf:params:jmap:error:"+kind ||
		(limit != "" && data["limit"] != limit) {
		t.Fatalf("status %d, problem %s", response.Code, response.Body)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("fixture read interruption") }

func TestRequestAdmission(t *testing.T) {
	config := testConfig(t)
	gateway, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer gateway.Close()

	for range maxConcurrent {
		gateway.admitted <- struct{}{}
	}
	request := httptest.NewRequest(http.MethodPost, "https://gateway.example/jmap", nil)
	response := httptest.NewRecorder()
	if _, _, ok := gateway.start(response, request); ok {
		t.Fatal("admission limit bypassed")
	}
	checkProblem(t, response, 503, "limit", "maxConcurrentRequests")
	busy := gatewayRequest(gateway, http.MethodPost, "/jmap", config.Token,
		[]byte(`{"using":["urn:ietf:params:jmap:core"],"methodCalls":[]}`))
	checkProblem(t, busy, 503, "limit", "maxConcurrentRequests")
	for range maxConcurrent {
		<-gateway.admitted
	}

	gateway.gate <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	response = httptest.NewRecorder()
	if _, _, ok := gateway.start(response, request.WithContext(ctx)); ok || response.Code != 503 {
		t.Fatal("request waited after cancellation")
	}
	<-gateway.gate
	if len(gateway.admitted) != 0 {
		t.Fatal("cancelled request leaked its admission slot")
	}
}

func TestConfigurationFailures(t *testing.T) {
	c := testConfig(t)
	dir := t.TempDir()
	for _, test := range []struct {
		name, content string
		mode          os.FileMode
	}{
		{"wide-permissions", "{}", 0644},
		{"too-large", strings.Repeat(" ", 65537), 0600},
		{"unknown-key", `{"Unexpected":123}`, 0600},
		{"multiple-objects", `{}{}`, 0600},
	} {
		path := filepath.Join(dir, test.name+".json")
		if err := os.WriteFile(path, []byte(test.content), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, test.mode); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(path); err == nil {
			t.Fatalf("accepted %s", test.name)
		}
	}
	for _, test := range []struct {
		name    string
		mutate  func(*Config)
		message string
	}{
		{"token", func(c *Config) { c.Token = "short" }, "invalid listener"},
		{"metadata vendor", func(c *Config) { c.MailboxMetadataVendor = "vendor.fake/extra" }, "invalid MailboxMetadataVendor"},
		{"address", func(c *Config) { c.SMTP.Address = "mail-without-port" }, "invalid SMTP address"},
		{"mode", func(c *Config) { c.IMAP.Mode = "cleartext" }, "IMAP requires tls"},
		{"imap CA", func(c *Config) { c.IMAP.CAFile = filepath.Join(dir, "missing") }, "cannot read upstream CA"},
		{"smtp CA", func(c *Config) { c.SMTP.CAFile = filepath.Join(dir, "wrong.pem") }, "invalid upstream CA"},
		{"state", func(c *Config) {
			c.StateDir = filepath.Join(dir, "missing", "sub")
			_ = os.WriteFile(filepath.Join(dir, "missing"), nil, 0600)
		}, "cannot create state directory"},
	} {
		t.Run(test.name, func(t *testing.T) {
			invalid := c
			test.mutate(&invalid)
			if invalid.SMTP.CAFile != "" {
				if err := os.WriteFile(invalid.SMTP.CAFile, []byte("not a CA"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			got, err := New(invalid)
			if err == nil {
				got.Close()
				t.Fatal("invalid configuration accepted")
			}
			if !strings.Contains(err.Error(), test.message) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestQueryAndSetValidation(t *testing.T) {
	account := testConfig(t)
	g, err := New(account)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	now := time.Now()
	first := &emailMeta{ID: "first", UID: 1, MailboxID: "m1", Received: now, Keywords: map[string]bool{}}
	second := &emailMeta{ID: "second", UID: 2, MailboxID: "m1", Received: now, Keywords: map[string]bool{}}
	older := &emailMeta{ID: "oldest", UID: 1, MailboxID: "m2", Received: now.Add(-time.Hour), Keywords: map[string]bool{}}
	together := &emailMeta{ID: "tie", UID: 2, MailboxID: "m2", Received: now, Keywords: map[string]bool{}}
	op := operation{g: g, snapshot: &snapshot{
		boxes:  []*box{{ID: "m1", Role: "drafts"}, {ID: "m2", Role: "inbox"}},
		emails: map[string]*emailMeta{"first": first, "second": second, "oldest": older, "tie": together},
	}, created: map[string]string{"reference": "second"}}
	for _, test := range []struct {
		args    object
		ids     string
		failure string
	}{
		{object{"limit": -1}, "", "invalidArguments"},
		{object{"filter": object{"unsupported": "x"}}, "", "unsupportedFilter"},
		{object{"filter": object{"inMailbox": 12}}, "", "invalidArguments"},
		{object{"sort": []object{{"property": "unknown"}}}, "", "unsupportedSort"},
		{object{"anchor": "not-there"}, "", "anchorNotFound"},
		{object{"anchor": "#reference", "anchorOffset": 1, "limit": 1}, "tie", ""},
		{object{"position": -2}, "tie,oldest", ""},
		{object{"sort": []object{{"property": "receivedAt", "isAscending": true}}}, "oldest,first,second,tie", ""},
		{object{"filter": object{"inMailbox": "m1"}}, "first,second", ""},
	} {
		result, failure := op.query(rawArgs(t, test.args))
		if failure != test.failure {
			t.Fatalf("%v had %s, expected %s", test.args, failure, test.failure)
		}
		if failure == "" && strings.Join(result["ids"].([]string), ",") != test.ids {
			t.Fatalf("%v returned %v, want %s", test.args, result, test.ids)
		}
	}

	for _, test := range []struct {
		kind    string
		args    object
		failure string
	}{
		{"Email", object{"invalid": true}, "invalidArguments"},
		{"Email", object{"onSuccessDestroyEmail": []string{"first"}}, "invalidArguments"},
		{"EmailSubmission", object{"onSuccessDestroyEmail": []string{"#"}}, "invalidArguments"},
		{"EmailSubmission", object{"onSuccessUpdateEmail": object{"#first": nil}}, "invalidArguments"},
		{"Email", object{"destroy": make([]string, maxSet+1)}, "requestTooLarge"},
		{"Email", object{"create": object{"invalid!": object{}}}, "invalidArguments"},
		{"Email", object{"ifInState": "old"}, "stateMismatch"},
	} {
		if _, kind := op.set(test.kind, rawArgs(t, test.args)); kind != test.failure {
			t.Fatalf("%v mapped to %s, want %s", test.args, kind, test.failure)
		}
	}
	result, kind := op.set("Email", rawArgs(t, object{
		"create":  object{"invalid": object{}},
		"update":  object{"first": object{"bad": nil}, "second": object{}, "missing": object{"keywords/$seen": nil}},
		"destroy": []string{"first"},
	}))
	if kind != "" || result["notCreated"].(object)["invalid"].(object)["type"] != "invalidProperties" ||
		result["notUpdated"].(object)["first"].(object)["type"] != "invalidPatch" ||
		result["notUpdated"].(object)["missing"].(object)["type"] != "notFound" ||
		result["notDestroyed"].(object)["first"].(object)["type"] != "forbidden" {
		t.Fatalf("mixed set returned unexpected outcomes: %v, %s", result, kind)
	}
	if status := imapFailure(&imap.Error{Type: imap.StatusResponseTypeNo}); status != "serverFail" ||
		imapFailure(io.EOF) != "serverUnavailable" {
		t.Fatal("incorrect IMAP status error mapping")
	}
}

func TestLedgerFaults(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if l, err := openLedger(dir, "account"); err == nil {
		l.lock.Close()
		t.Fatal("readable state directory accepted")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "submissions.json")
	for _, input := range []string{
		`not JSON`,
		`{"Account":"another","Records":{}}`,
		`{"Account":"account","Records":{"invalid":{}}}`,
	} {
		if err := os.WriteFile(target, []byte(input), 0600); err != nil {
			t.Fatal(err)
		}
		if l, err := openLedger(dir, "account"); err == nil {
			l.lock.Close()
			t.Fatal("invalid state accepted")
		}
	}
	if err := os.WriteFile(target, []byte(`{"Account":"account","Records":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	l, err := openLedger(dir, "account")
	if err != nil {
		t.Fatal(err)
	}
	defer l.lock.Close()
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := l.save(); err == nil || !l.failed {
		t.Fatal("rename failure must stop further writes")
	}
	if err := l.save(); err == nil || !strings.Contains(err.Error(), "requires recovery") {
		t.Fatal("failed ledger did not block subsequent writes")
	}
}
