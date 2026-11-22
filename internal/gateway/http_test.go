package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
)

func TestPreviousResultReferenceValidation(t *testing.T) {
	previous := map[string]invocationResult{
		"one": {name: "Core/echo", args: object{
			"nested":  []any{object{"ids": []string{"a", "b"}}, object{"ids": []string{"c"}}},
			"missing": []any{object{}},
		}},
		"bad": {name: "Core/echo", args: object{"cannotEncode": make(chan int)}},
	}
	for _, test := range []struct {
		key, prior, name, path string
		failure                bool
	}{
		{"#", "one", "Core/echo", "/nested/1/ids/0", false},
		{"#a", "one", "error", "/nested", true},
		{"#a", "absent", "Core/echo", "/nested", true},
		{"#a", "bad", "Core/echo", "/nested", true},
		{"#a", "one", "Core/echo", "nested", true},
		{"#a", "one", "Core/echo", strings.Repeat("/nested", 21), true},
		{"#a", "one", "Core/echo", "/missing/*/ids", true},
		{"#a", "one", "Core/echo", "/nested/1/ids/0", false},
		{"#a", "one", "Core/echo", "/nested/*/ids", false},
	} {
		args := rawArgs(t, object{test.key: object{"resultOf": test.prior, "name": test.name, "path": test.path}})
		if result := resolveArgs(args, previous); (result != "") != test.failure {
			t.Fatalf("unexpected result for %q, %q, %q", test.prior, test.name, test.path)
		}
		if !test.failure {
			want := `"c"`
			if strings.Contains(test.path, "*") {
				want = `["a","b","c"]`
			}
			if string(args[test.key[1:]]) != want {
				t.Fatalf("path %s returned %s, want %s", test.path, args[test.key[1:]], want)
			}
		}
	}
}

func TestMethodBatchAfterBackendTimeout(t *testing.T) {
	listener := listenTCP(t)
	c := testConfig(t)
	c.IMAP.Address = listener.Addr().String()
	g, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	const request = `{"using":["urn:ietf:params:jmap:mail","urn:ietf:params:jmap:submission"],
		"methodCalls":[["Mailbox/get",{"accountId":"sender"},"one"],["Identity/get",{"accountId":"sender"},"two"]]}`
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		conn, err := listener.Accept()
		cancel()
		if err == nil {
			_ = conn.Close()
		}
	}()
	req := httptest.NewRequest(http.MethodPost, "https://gateway.example/jmap", strings.NewReader(request)).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	g.ServeHTTP(res, req)
	var response struct {
		Responses [][3]json.RawMessage `json:"methodResponses"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &response); err != nil || len(response.Responses) != 2 {
		t.Fatalf("unexpected response %s", res.Body)
	}
	for _, item := range response.Responses {
		if string(item[0]) != `"error"` || string(item[1]) != `{"type":"serverUnavailable"}` {
			t.Fatalf("unexpected timeout result %s", item)
		}
	}
}

func TestBoundedConnectionCancellation(t *testing.T) {
	listener := listenTCP(t)
	received := make(chan net.Conn, 1)
	go func() {
		conn, _ := listener.Accept()
		received <- conn
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, closeConn, err := dial(ctx, listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer closeConn()
	server := <-received
	defer server.Close()
	if err := conn.SetDeadline(time.Now().Add(24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	cancel()
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	if n, err := server.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatal("context cancellation left upstream connection open")
	}
}

func TestDownloadAndGetFailures(t *testing.T) {
	cert, ca := testTLS(t)
	for _, test := range []struct {
		fault, body, lookup string
		downloadStatus      int
		getResponse         string
	}{
		{"body-gone", "Subject: fixture\r\n\r\nhello\r\n", "raw", 404, "Email/get"},
		{"body-rejected", "Subject: fixture\r\n\r\nhello\r\n", "raw", 503, "error"},
		{"", "bad header\r\n\r\nhello\r\n", "part", 404, "error"},
		{"", "Subject: fixture\r\n\r\nhello\r\n", "missing", 404, "Email/get"},
		{"unavailable", "", "raw", 503, "error"},
		{"busy", "", "raw", 503, ""},
	} {
		t.Run(test.fault+test.lookup, func(t *testing.T) {
			c := testConfig(t)
			c.IMAP.CAFile = ca
			address, user := serveTestIMAP(t, c.IMAP, cert, imap.CapSet{imap.CapIMAP4rev1: {}}, func(session imapserver.Session) imapserver.Session {
				return imapFaultSession{Session: session, fault: test.fault}
			})
			c.IMAP.Address = address
			if test.fault == "unavailable" {
				closed := listenTCP(t)
				c.IMAP.Address = closed.Addr().String()
				_ = closed.Close()
			}
			id := emailID(mailboxID(c.AccountID, "INBOX"), 1, 1)
			if test.body != "" {
				data, err := user.Append("INBOX", strings.NewReader(test.body), &imap.AppendOptions{Time: time.Now()})
				if err != nil {
					t.Fatal(err)
				}
				id = emailID(mailboxID(c.AccountID, "INBOX"), data.UIDValidity, data.UID)
			}
			g, err := New(c)
			if err != nil {
				t.Fatal(err)
			}
			defer g.Close()
			blob := "b-" + id[2:]
			if test.lookup == "part" {
				blob = partBlobID(id, "1")
			}
			if test.lookup == "missing" {
				blob = "b-" + strings.Repeat("z", 43)
			}
			if test.fault == "busy" {
				for range maxConcurrent {
					g.admitted <- struct{}{}
				}
			}
			result := gatewayRequest(g, http.MethodGet, "/download/"+c.AccountID+"/"+blob+"/sample", c.Token, nil)
			if result.Code != test.downloadStatus {
				t.Fatalf("HTTP %d, want %d", result.Code, test.downloadStatus)
			}
			if test.getResponse != "" {
				call := gatewayCalls(t, g, c.Token, [3]any{"Email/get", object{"accountId": c.AccountID, "ids": []string{id}}, "get"})[0]
				if call.Name != test.getResponse {
					t.Fatalf("get returned %v", call)
				}
				if test.fault == "body-gone" && len(call.Args["notFound"].([]any)) != 1 {
					t.Fatal("disappeared message reported present")
				}
			}
		})
	}
}
