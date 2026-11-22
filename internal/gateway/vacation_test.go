package gateway

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

func vacationConfig(t *testing.T) (Config, *tls.Config) {
	t.Helper()
	cfg := testConfig(t)
	cert, ca := testTLS(t)
	cfg.ManageSieve = &Upstream{Address: "127.0.0.1:4190", Mode: "starttls", Username: "testuser", Password: "testpass", CAFile: ca}
	return cfg, cert
}

func serveTestSieve(t *testing.T, config *Upstream, cert *tls.Config, fault string) string {
	t.Helper()
	listener := listenTCP(t)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		var script []byte
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			if err := testSieveConversation(conn, cert, config, &script, fault); err != nil {
				t.Errorf("ManageSieve peer: %v", err)
			}
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-finished
	})
	return listener.Addr().String()
}

func testSieveConversation(conn net.Conn, cert *tls.Config, config *Upstream, script *[]byte, fault string) error {
	if fault == "greeting" {
		_, err := io.WriteString(conn, "BYE \"Unavailable\"\r\n")
		return err
	}
	if _, err := io.WriteString(conn, "\"STARTTLS\"\r\nOK\r\n"); err != nil {
		return err
	}
	reader := bufio.NewReader(conn)
	if line, err := reader.ReadString('\n'); err != nil || line != "STARTTLS\r\n" {
		return fmt.Errorf("client did not negotiate TLS")
	}
	if fault == "starttls" {
		_, err := io.WriteString(conn, "NO\r\n")
		return err
	}
	if _, err := io.WriteString(conn, "OK\r\n"); err != nil {
		return err
	}
	secure := tls.Server(conn, cert)
	if err := secure.Handshake(); err != nil {
		if fault == "certificate" {
			return nil
		}
		return err
	}
	if fault == "postTLS" {
		return nil
	}
	if _, err := io.WriteString(secure, "\"SASL\" \"PLAIN\"\r\nOK\r\n"); err != nil {
		return err
	}
	reader = bufio.NewReader(secure)
	auth := base64.StdEncoding.EncodeToString([]byte("\x00" + config.Username + "\x00" + config.Password))
	if line, err := reader.ReadString('\n'); err != nil || line != "AUTHENTICATE \"PLAIN\" \""+auth+"\"\r\n" {
		return fmt.Errorf("unexpected authentication command")
	}
	if fault == "auth" {
		_, err := io.WriteString(secure, "NO\r\n")
		return err
	}
	if _, err := io.WriteString(secure, "OK\r\n"); err != nil {
		return err
	}
	if line, err := reader.ReadString('\n'); err != nil || line != "GETSCRIPT \"jmap-vacation\"\r\n" {
		return fmt.Errorf("unexpected GETSCRIPT command")
	}
	if fault == "get" {
		_, err := io.WriteString(secure, "NO\r\n")
		return err
	}
	if *script == nil {
		if _, err := io.WriteString(secure, "NO (NONEXISTENT) \"Missing\"\r\n"); err != nil {
			return err
		}
	} else if _, err := fmt.Fprintf(secure, "{%d}\r\n%s\r\nOK\r\n", len(*script), *script); err != nil {
		return err
	}
	line, err := reader.ReadString('\n')
	if err == io.EOF {
		return nil
	}
	var size int
	if err != nil {
		return err
	}
	if _, err := fmt.Sscanf(line, "PUTSCRIPT \"jmap-vacation\" {%d+}", &size); err != nil || size < 1 || size > maxVacationScript {
		return fmt.Errorf("unexpected PUTSCRIPT command")
	}
	payload := make([]byte, size+2)
	if _, err := io.ReadFull(reader, payload); err != nil || string(payload[size:]) != "\r\n" {
		return fmt.Errorf("invalid PUTSCRIPT literal")
	}
	if fault == "put" {
		_, err := io.WriteString(secure, "NO\r\n")
		return err
	}
	*script = payload[:size]
	_, err = io.WriteString(secure, "OK\r\n")
	return err
}

func vacationCall(t *testing.T, g *Gateway, cfg Config, method string, args object) (string, object) {
	t.Helper()
	if _, ok := args["accountId"]; !ok {
		args["accountId"] = cfg.AccountID
	}
	raw, err := json.Marshal(object{"using": []string{core, vacationCapability}, "methodCalls": [][3]any{{"VacationResponse/" + method, args, "vacation"}}})
	if err != nil {
		t.Fatal(err)
	}
	response := gatewayRequest(g, http.MethodPost, "/jmap", cfg.Token, raw)
	var result struct{ MethodResponses [][3]json.RawMessage }
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil || len(result.MethodResponses) != 1 {
		t.Fatalf("vacation HTTP result: %d, %s", response.Code, response.Body)
	}
	var name string
	var payload object
	if json.Unmarshal(result.MethodResponses[0][0], &name) != nil || json.Unmarshal(result.MethodResponses[0][1], &payload) != nil {
		t.Fatal("bad method response")
	}
	return name, payload
}

func TestVacationResponseOverTLS(t *testing.T) {
	cfg, cert := vacationConfig(t)
	cfg.ManageSieve.Address = serveTestSieve(t, cfg.ManageSieve, cert, "")
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	if g.session["capabilities"].(object)[vacationCapability] == nil ||
		g.session["accounts"].(object)[cfg.AccountID].(object)["accountCapabilities"].(object)[vacationCapability] == nil ||
		g.session["primaryAccounts"].(object)[vacationCapability] != cfg.AccountID {
		t.Fatalf("missing vacation capability")
	}
	_, before := vacationCall(t, g, cfg, "get", object{})
	defaults := before["list"].([]any)[0].(map[string]any)
	if defaults["id"] != vacationID || defaults["isEnabled"] != false || defaults["textBody"] != nil {
		t.Fatalf("unexpected defaults: %v", defaults)
	}
	_, set := vacationCall(t, g, cfg, "set", object{"ifInState": before["state"],
		"create": object{"new": object{}}, "destroy": []string{vacationID, "missing"},
		"update": object{"missing": object{}, vacationID: object{
			"id": vacationID, "isEnabled": true, "fromDate": "2026-11-19T12:00:00Z", "toDate": "2026-11-24T12:00:00Z",
			"subject": "Ääni", "textBody": "Hei\n.\nBye", "htmlBody": "<p>Hei</p>",
		}}})
	if set["oldState"] == set["newState"] || set["updated"] == nil ||
		set["notCreated"].(map[string]any)["new"].(map[string]any)["type"] != "singleton" ||
		set["notUpdated"].(map[string]any)["missing"].(map[string]any)["type"] != "notFound" ||
		set["notDestroyed"].(map[string]any)[vacationID].(map[string]any)["type"] != "singleton" ||
		set["notDestroyed"].(map[string]any)["missing"].(map[string]any)["type"] != "notFound" {
		t.Fatalf("unexpected Set response: %v", set)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	g = reopened
	_, after := vacationCall(t, g, cfg, "get", object{"ids": []string{"missing", vacationID, vacationID, "missing"}, "properties": []string{"textBody"}})
	record := after["list"].([]any)[0].(map[string]any)
	if len(after["list"].([]any)) != 1 || len(record) != 2 || record["id"] != vacationID || record["textBody"] != "Hei\n.\nBye" ||
		after["state"] != set["newState"] || !slices.Equal(after["notFound"].([]any), []any{"missing"}) {
		t.Fatalf("restart did not preserve settings: %v", after)
	}
	for _, test := range []struct {
		method, code string
		args         object
	}{
		{"get", "invalidArguments", object{"typo": true}},
		{"get", "invalidArguments", object{"properties": []string{"typo"}}},
		{"get", "requestTooLarge", object{"ids": make([]string, maxGet+1)}},
		{"get", "accountNotFound", object{"accountId": "another"}},
		{"set", "invalidArguments", object{"onSuccessUpdateEmail": nil}},
		{"set", "requestTooLarge", object{"destroy": make([]string, maxSet+1)}},
		{"set", "invalidArguments", object{"create": object{"#bad": object{}}}},
		{"set", "stateMismatch", object{"ifInState": before["state"]}},
	} {
		if name, result := vacationCall(t, g, cfg, test.method, test.args); name != "error" || result["type"] != test.code {
			t.Fatalf("got %v %v, want %s", name, result, test.code)
		}
	}
	_, invalid := vacationCall(t, g, cfg, "set", object{"update": object{vacationID: nil}})
	if invalid["notUpdated"].(map[string]any)[vacationID].(map[string]any)["type"] != "invalidPatch" {
		t.Fatalf("invalid patch: %v", invalid)
	}
	_, noop := vacationCall(t, g, cfg, "set", object{"update": object{vacationID: object{}}})
	if noop["newState"] != after["state"] || noop["updated"] == nil {
		t.Fatalf("unchanged update: %v", noop)
	}
	_, dateUpdate := vacationCall(t, g, cfg, "set", object{"update": object{vacationID: object{"toDate": "2026-11-25T12:00:00Z"}}})
	_, dated := vacationCall(t, g, cfg, "get", object{})
	_, invalidDate := vacationCall(t, g, cfg, "set", object{"update": object{vacationID: object{"fromDate": "2026-12-30T00:00:00Z"}}})
	if dateUpdate["newState"] == after["state"] || dated["state"] != dateUpdate["newState"] ||
		dated["list"].([]any)[0].(map[string]any)["toDate"] != "2026-11-25T12:00:00Z" ||
		invalidDate["notUpdated"] == nil || invalidDate["newState"] != dated["state"] {
		t.Fatalf("date update did not survive a read or an invalid patch: %v %v %v", dateUpdate, dated, invalidDate)
	}
	_, disabled := vacationCall(t, g, cfg, "set", object{"update": object{vacationID: object{"isEnabled": false}}})
	if disabled["newState"] == dated["state"] {
		t.Fatalf("disable did not change state: %v", disabled)
	}
}

func TestVacationResponseFailures(t *testing.T) {
	for _, test := range []struct{ fault, code, method string }{
		{"dial", "serverUnavailable", "get"}, {"greeting", "serverUnavailable", "get"}, {"starttls", "serverFail", "set"},
		{"certificate", "serverUnavailable", "get"}, {"postTLS", "serverUnavailable", "get"}, {"auth", "serverFail", "get"},
		{"get", "serverFail", "get"}, {"get", "serverFail", "set"}, {"put", "serverFail", "set"},
	} {
		t.Run(test.fault+"-"+test.method, func(t *testing.T) {
			cfg, cert := vacationConfig(t)
			if test.fault == "dial" {
				listener := listenTCP(t)
				cfg.ManageSieve.Address = listener.Addr().String()
				_ = listener.Close()
			} else {
				cfg.ManageSieve.Address = serveTestSieve(t, cfg.ManageSieve, cert, test.fault)
			}
			if test.fault == "certificate" {
				cfg.ManageSieve.CAFile = ""
			}
			g, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer g.Close()
			args := object{}
			if test.method == "set" {
				args["update"] = object{vacationID: object{"isEnabled": true}}
			}
			if name, result := vacationCall(t, g, cfg, test.method, args); name != "error" || result["type"] != test.code {
				t.Fatalf("got %s %v, want %s", name, result, test.code)
			}
		})
	}
	cfg, _ := vacationConfig(t)
	cfg.ManageSieve.CAFile = "/missing/vacation/CA"
	if _, err := New(cfg); err == nil {
		t.Fatal("invalid ManageSieve CA accepted")
	}
	cfg.ManageSieve.Mode = "cleartext"
	if _, err := New(cfg); err == nil {
		t.Fatal("invalid ManageSieve mode accepted")
	}
}

func TestVacationScriptAndValidation(t *testing.T) {
	current := vacationResponse{}
	raw, err := json.Marshal(object{"id": "wrong", "subject": "newline\r\n", "htmlBody": strings.Repeat("x", maxVacationBody+1),
		"textBody": "bad\x00", "fromDate": "2026-11-24T12:00:00+00:00", "toDate": "bad",
		"missing": true, "isEnabled": nil})
	if err != nil {
		t.Fatal(err)
	}
	_, failure := current.updated(raw)
	actual := failure["properties"].([]string)
	slices.Sort(actual)
	expected := []string{"fromDate", "htmlBody", "id", "isEnabled", "missing", "subject", "textBody", "toDate"}
	if !slices.Equal(actual, expected) {
		t.Fatalf("unexpected invalid properties: %v", failure)
	}
	if _, failure := current.updated([]byte(`{"fromDate":"2026-11-23T00:00:00Z","toDate":"2026-11-22T00:00:00Z"}`)); failure == nil {
		t.Fatal("reversed dates accepted")
	}
	settings, failure := current.updated([]byte(`{"isEnabled":true,"subject":"A\"B\\C","textBody":".\n.hidden","htmlBody":"<p>Hi</p>","toDate":"2026-11-24T00:00:00Z"}`))
	script := settings.script("sender@example.test")
	for _, value := range []string{`currentdate :zone "+0000" :value "lt" "iso8601" "2026-11-24T00:00:00+00:00"`,
		` :subject "A\"B\\C"`, "multipart/alternative", "\r\n..\r\n..hidden\r\n", "\r\n.\r\n;\r\n"} {
		if !bytes.Contains(script, []byte(value)) {
			t.Fatalf("missing %q in compiled Sieve script", value)
		}
	}
	var decoded vacationResponse
	if failure != nil || !decodeVacationScript(script, &decoded) || digest(decoded) != digest(settings) {
		t.Fatalf("metadata roundtrip: %v %+v", failure, decoded)
	}
	if compiled := (vacationResponse{Enabled: true}).script("sender@example.test"); !bytes.Contains(compiled, []byte("I am currently away")) {
		t.Fatal("missing default body")
	}
	if decodeVacationScript(append(script, []byte("discard;\r\n")...), &decoded) {
		t.Fatal("externally changed script retained gateway ownership")
	}
}

type closedSieveWriter struct{}

func (closedSieveWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestSieveBoundedResponses(t *testing.T) {
	failing := &sieveClient{reader: bufio.NewReader(strings.NewReader("")), writer: closedSieveWriter{}}
	if failure := failing.command("STARTTLS\r\n"); failure != "serverUnavailable" {
		t.Fatalf("write failure: %s", failure)
	}
	if _, failure := failing.getVacation(); failure != "serverUnavailable" {
		t.Fatalf("GETSCRIPT write failure: %s", failure)
	}
	for _, test := range []struct{ name, response, want string }{
		{"connection closed", "", "serverUnavailable"},
		{"literal too large", fmt.Sprintf("{%d}\r\n", maxVacationScript+1), "serverFail"},
		{"truncated script", "{10}\r\nshort", "serverUnavailable"},
		{"missing status", "{3}\r\nabc\r\n", "serverUnavailable"},
		{"different script owner", "{3}\r\nabc\r\nOK\r\n", "serverFail"},
	} {
		client := &sieveClient{reader: bufio.NewReader(strings.NewReader(test.response)), writer: io.Discard}
		if _, failure := client.getVacation(); failure != test.want {
			t.Fatalf("%s: got %s, want %s", test.name, failure, test.want)
		}
	}
	closed := &sieveClient{reader: bufio.NewReader(strings.NewReader("")), writer: io.Discard}
	if failure := closed.command("STARTTLS\r\n"); failure != "serverUnavailable" {
		t.Fatalf("missing response: %s", failure)
	}
	oversized := &sieveClient{reader: bufio.NewReader(strings.NewReader(strings.Repeat("\"SASL\" \"PLAIN\"\r\n", 33)))}
	if failure := oversized.greeting(); failure != "serverFail" {
		t.Fatalf("invalid greeting: %s", failure)
	}
}
