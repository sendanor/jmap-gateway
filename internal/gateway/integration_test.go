package gateway

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
)

func listenTCP(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func testTLS(t *testing.T) (*tls.Config, string) {
	t.Helper()
	// Use net/http's loopback certificate and trust it only in this fixture.
	server := httptest.NewTLSServer(http.NotFoundHandler())
	server.Close()
	config := server.TLS.Clone()
	path := filepath.Join(t.TempDir(), "ca.pem")
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: config.Certificates[0].Certificate[0]})
	if err := os.WriteFile(path, cert, 0600); err != nil {
		t.Fatal(err)
	}
	return config, path
}

func serveTestIMAP(t *testing.T, config Upstream, cert *tls.Config, caps imap.CapSet, wrap func(imapserver.Session) imapserver.Session) (string, *imapmemserver.User) {
	t.Helper()
	memory := imapmemserver.New()
	user := imapmemserver.NewUser(config.Username, config.Password)
	memory.AddUser(user)
	for _, name := range []string{"INBOX", "Drafts", "Drafts/Child", "Plain"} {
		if err := user.Create(name, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := user.Subscribe("Drafts"); err != nil {
		t.Fatal(err)
	}
	server := imapserver.New(&imapserver.Options{
		Caps: caps, Logger: log.New(io.Discard, "", 0),
		NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			session := memory.NewSession()
			if wrap != nil {
				session = wrap(session)
			}
			return session, nil, nil
		},
	})
	listener := tls.NewListener(listenTCP(t), cert)
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
		_ = server.Close()
	})
	return listener.Addr().String(), user
}

type smtpFixture struct {
	received chan string
	mailFrom chan string
	rcptTo   chan string
	done     chan error
}

func serveTestSMTP(t *testing.T, config Upstream, cert *tls.Config, failure string) (string, *smtpFixture) {
	t.Helper()
	fixture := &smtpFixture{received: make(chan string, 1), mailFrom: make(chan string, 1),
		rcptTo: make(chan string, maxSubmissionRecipients), done: make(chan error, 1)}
	listener := listenTCP(t)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			fixture.done <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
		fixture.done <- smtpConversation(conn, config, cert, failure, fixture)
	}()
	return listener.Addr().String(), fixture
}

func smtpConversation(conn net.Conn, config Upstream, cert *tls.Config, failure string, fixture *smtpFixture) error {
	secured := config.Mode == "tls"
	if secured {
		conn = tls.Server(conn, cert)
	}
	reader := bufio.NewReader(conn)
	reply := func(s string) error {
		_, err := io.WriteString(conn, s+"\r\n")
		return err
	}
	greeting := "220 smtp.example.test"
	if failure == "greeting" {
		return reply("421 unavailable")
	}
	if err := reply(greeting); err != nil {
		return err
	}
	for {
		line, err := reader.ReadString('\n')
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		line = strings.TrimRight(line, "\r\n")
		command, args, _ := strings.Cut(line, " ")
		switch command {
		case "EHLO":
			if secured {
				extensions := "250-smtp.example.test\r\n"
				switch failure {
				case "dsn":
					extensions += "250-DSN\r\n"
				case "size":
					extensions += "250-SIZE 80\r\n"
				case "smtputf8":
					extensions += "250-8BITMIME\r\n250-SMTPUTF8\r\n"
				case "utf8-without-8bit":
					extensions += "250-SMTPUTF8\r\n"
				case "8bitmime":
					extensions += "250-8BITMIME\r\n"
				}
				err = reply(extensions + "250 AUTH PLAIN")
			} else {
				err = reply("250-smtp.example.test\r\n250 STARTTLS")
			}
		case "STARTTLS":
			if failure == "starttls" {
				return reply("454 unavailable")
			}
			if err = reply("220 start TLS"); err != nil {
				return err
			}
			conn = tls.Server(conn, cert)
			reader = bufio.NewReader(conn)
			secured = true
		case "AUTH":
			auth := base64.StdEncoding.EncodeToString([]byte("\x00" + config.Username + "\x00" + config.Password))
			if !secured || args != "PLAIN "+auth {
				return fmt.Errorf("unexpected SMTP authentication")
			}
			if failure == "auth" {
				err = reply("535 authentication failed")
			} else {
				err = reply("235 authenticated")
			}
		case "MAIL", "RCPT", "DATA":
			if command == "MAIL" {
				fixture.mailFrom <- args
			}
			if command == "RCPT" {
				fixture.rcptTo <- args
			}
			if command == "DATA" && failure == "disconnect-during-data" {
				return reply("354 send message")
			}
			if command == "RCPT" && failure == "selective" && strings.HasPrefix(args, "TO:<reject-") {
				if err := reply("550 rejected"); err != nil {
					return err
				}
				continue
			}
			if command == "RCPT" && failure == "temporary" && strings.HasPrefix(args, "TO:<retry-") {
				if err := reply("450 try again"); err != nil {
					return err
				}
				continue
			}
			if failure == strings.ToLower(command) {
				return reply("550 rejected")
			}
			if command == "RCPT" && failure == "dsn" {
				if strings.HasPrefix(args, "TO:<plain@") {
					err = reply("251 2.1.5 Will forward")
				} else {
					err = reply("250-2.1.5 Recipient accepted\r\n250 2.1.5 Recipient eligible for relay")
				}
				break
			}
			if command != "DATA" {
				err = reply("250 OK")
				break
			}
			if err := reply("354 send message"); err != nil {
				return err
			}
			var body strings.Builder
			for {
				part, err := reader.ReadString('\n')
				if err != nil {
					return err
				}
				if part == ".\r\n" {
					break
				}
				body.WriteString(part)
			}
			fixture.received <- body.String()
			switch failure {
			case "lost-reply":
				return nil
			case "after-data":
				return reply("451 temporary failure")
			default:
				return reply("250 queued")
			}
		case "*":
			err = reply("501 authentication cancelled")
		case "QUIT":
			return reply("221 bye")
		default:
			return fmt.Errorf("unexpected SMTP command %q", command)
		}
		if err != nil {
			return err
		}
	}
}

func gatewayRequest(g *Gateway, method, path, token string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "https://gateway.example"+path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	g.ServeHTTP(res, req)
	return res
}

func gatewayCalls(t *testing.T, g *Gateway, token string, calls ...[3]any) []struct {
	Name string
	Args object
} {
	t.Helper()
	raw, err := json.Marshal(object{"using": []string{core, mailCapability, submissionCapability}, "methodCalls": calls})
	if err != nil {
		t.Fatal(err)
	}
	response := gatewayRequest(g, http.MethodPost, "/jmap", token, raw)
	var envelope struct {
		Responses [][3]json.RawMessage `json:"methodResponses"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &envelope) != nil || len(envelope.Responses) != len(calls) {
		t.Fatalf("JMAP HTTP %d, body %s", response.Code, response.Body)
	}
	result := make([]struct {
		Name string
		Args object
	}, len(calls))
	for i, row := range envelope.Responses {
		if json.Unmarshal(row[0], &result[i].Name) != nil || json.Unmarshal(row[1], &result[i].Args) != nil {
			t.Fatalf("invalid response at index %d", i)
		}
	}
	return result
}

func TestGatewayMailFlowOverTLS(t *testing.T) {
	cert, ca := testTLS(t)
	for _, test := range []struct{ mode, fault, kind string }{
		{"starttls", "", ""},
		{"tls", "", ""},
		{"tls", "greeting", "serverUnavailable"},
		{"starttls", "starttls", "serverUnavailable"},
		{"tls", "auth", "forbiddenToSend"},
		{"tls", "mail", "forbiddenMailFrom"},
		{"tls", "rcpt", "invalidRecipients"},
		{"tls", "data", "forbiddenToSend"},
		{"tls", "after-data", "serverUnavailable"},
		{"tls", "lost-reply", "serverFail"},
	} {
		t.Run(test.mode+"/"+test.fault, func(t *testing.T) {
			config := testConfig(t)
			config.IMAP.CAFile = ca
			config.IMAP.Address, _ = serveTestIMAP(t, config.IMAP, cert, imap.CapSet{
				imap.CapIMAP4rev1: {}, imap.CapUIDPlus: {}, imap.CapListExtended: {},
			}, nil)
			config.DraftsMailbox = "Drafts"
			config.SMTP.CAFile = ca
			config.SMTP.Mode = test.mode
			var smtp *smtpFixture
			config.SMTP.Address, smtp = serveTestSMTP(t, config.SMTP, cert, test.fault)
			g, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			defer g.Close()
			account := config.AccountID
			folders := gatewayCalls(t, g, config.Token, [3]any{"Mailbox/get", object{"accountId": account}, "folders"})[0]
			if folders.Name != "Mailbox/get" {
				t.Fatalf("mailboxes failed: %v", folders.Args)
			}
			drafts, inbox := "", ""
			for _, item := range folders.Args["list"].([]any) {
				m := item.(map[string]any)
				switch m["role"] {
				case "drafts":
					drafts = m["id"].(string)
				case "inbox":
					inbox = m["id"].(string)
				}
			}
			if drafts == "" || inbox == "" {
				t.Fatal("missing mailbox roles")
			}
			draft := object{
				"mailboxIds": map[string]bool{drafts: true}, "from": []object{{"email": config.IdentityEmail}},
				"to": []object{{"email": "recipient@example.test"}}, "subject": "Coverage flow",
				"textBody":   []object{{"partId": "1", "type": "text/plain"}},
				"bodyValues": object{"1": object{"value": "Hello over IMAP and SMTP"}},
			}
			flow := gatewayCalls(t, g, config.Token,
				[3]any{"Email/set", object{"accountId": account, "create": object{"draft": draft}}, "create"},
				[3]any{"Email/query", object{"accountId": account, "filter": object{"inMailbox": drafts},
					"calculateTotal": true, "sort": []object{{"property": "receivedAt"}}}, "query"},
				[3]any{"Email/get", object{"accountId": account, "fetchTextBodyValues": true,
					"#ids": object{"resultOf": "query", "name": "Email/query", "path": "/ids"}}, "get"},
				[3]any{"EmailSubmission/set", object{"accountId": account, "create": object{
					"send": object{"emailId": "#draft", "identityId": identityID},
				}}, "send"},
			)
			if flow[0].Name != "Email/set" || flow[1].Name != "Email/query" ||
				flow[2].Name != "Email/get" || flow[3].Name != "EmailSubmission/set" {
				t.Fatalf("mail flow failed: %v", flow)
			}
			if flow[0].Args["created"] == nil || flow[1].Args["total"] != float64(1) {
				t.Fatalf("draft missing: %v", flow[:2])
			}
			record := flow[2].Args["list"].([]any)[0].(map[string]any)
			id := record["id"].(string)
			if record["subject"] != "Coverage flow" || record["bodyValues"].(map[string]any)["1"].(map[string]any)["value"] != "Hello over IMAP and SMTP\n" {
				t.Fatal("Unexpected IMAP message")
			}
			if test.kind == "" {
				entry := flow[3].Args["created"].(map[string]any)["send"].(map[string]any)
				submissionID := entry["id"].(string)
				delta := gatewayCalls(t, g, config.Token, [3]any{"EmailSubmission/changes", object{
					"accountId": account, "sinceState": flow[3].Args["oldState"],
				}, "delta"})[0]
				if delta.Name != "EmailSubmission/changes" || delta.Args["hasMoreChanges"] != false ||
					delta.Args["created"].([]any)[0] != submissionID || delta.Args["newState"] != flow[3].Args["newState"] {
					t.Fatalf("missing accepted submission change: %v", delta)
				}
				status := gatewayCalls(t, g, config.Token, [3]any{"EmailSubmission/get", object{"accountId": account, "ids": []string{submissionID}}, "status"})[0]
				if status.Args["list"].([]any)[0].(map[string]any)["undoStatus"] != "final" {
					t.Fatalf("SMTP acceptance missing: %v", status.Args)
				}
				for _, seen := range []any{true, nil} {
					updates := gatewayCalls(t, g, config.Token,
						[3]any{"Email/set", object{"accountId": account, "update": object{id: object{"keywords/$seen": seen}}}, "set"},
						[3]any{"Email/get", object{"accountId": account, "ids": []string{id}, "properties": []string{"keywords"}}, "get"},
					)
					_, updated := updates[0].Args["updated"].(map[string]any)[id]
					flags := updates[1].Args["list"].([]any)[0].(map[string]any)["keywords"].(map[string]any)
					if !updated || (flags["$seen"] == true) != (seen == true) {
						t.Fatalf("seen flag mismatch: %v", updates)
					}
				}
				path := "/download/" + account + "/" + record["blobId"].(string) + "/message.eml"
				got := gatewayRequest(g, http.MethodGet, path, config.Token, nil)
				if got.Code != http.StatusOK || !strings.Contains(got.Body.String(), "Hello over IMAP and SMTP") {
					t.Fatal("raw download failed")
				}
				part := record["textBody"].([]any)[0].(map[string]any)["blobId"].(string)
				got = gatewayRequest(g, http.MethodGet, "/download/"+account+"/"+part+"/part.txt", config.Token, nil)
				if got.Code != http.StatusOK || !strings.HasPrefix(got.Body.String(), "Hello over IMAP and SMTP") {
					t.Fatal("part download failed")
				}
			} else {
				errorObject := flow[3].Args["notCreated"].(map[string]any)["send"].(map[string]any)
				if errorObject["type"] != test.kind {
					t.Fatalf("SMTP fault %s mapped to %v", test.fault, errorObject)
				}
				extractTestMessageKey(t, smtp, test.fault)
				reserved := len(g.ledger.records) != 0
				if (test.fault == "lost-reply") != reserved {
					t.Fatal("incorrect durable reservation after SMTP failure")
				}
			}
			select {
			case err := <-smtp.done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("SMTP conversation did not end")
			}
			if test.kind == "" {
				extractTestMessageKey(t, smtp, "")
			}
		})
	}
}

func extractTestMessageKey(t *testing.T, fixture *smtpFixture, fault string) string {
	t.Helper()
	select {
	case body := <-fixture.received:
		if !strings.Contains(body, "Hello over IMAP and SMTP") {
			t.Fatal("message body missing from SMTP DATA")
		}
		message, err := mail.ReadMessage(strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		match := gatewayMessageID.FindStringSubmatch(message.Header.Get("Message-ID"))
		if match == nil {
			t.Fatal("SMTP body missing gateway Message-ID")
		}
		return match[1]
	default:
		if fault == "" || fault == "after-data" || fault == "lost-reply" {
			t.Fatal("SMTP DATA was not received")
		}
		return ""
	}
}
