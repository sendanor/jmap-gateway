package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
)

type receivedEvent struct {
	name, id string
	data     object
}

func readTestEvent(t *testing.T, reader *bufio.Reader) receivedEvent {
	t.Helper()
	var actual receivedEvent
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\n" {
			return actual
		}
		key, value, _ := strings.Cut(strings.TrimSuffix(line, "\n"), ": ")
		switch key {
		case "event":
			actual.name = value
		case "id":
			actual.id = value
		case "data":
			if err := json.Unmarshal([]byte(value), &actual.data); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func openTestEvents(t *testing.T, server *httptest.Server, token, query, lastID string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, server.URL+"/events?"+query, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Last-Event-ID", lastID)
	client := *server.Client()
	client.Timeout = 12 * time.Second
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "text/event-stream" {
		response.Body.Close()
		t.Fatalf("unexpected event response: %d %v", response.StatusCode, response.Header)
	}
	return response
}

func TestEventSourceResumesExternalChangesOverTLS(t *testing.T) {
	cfg := testConfig(t)
	cert, ca := testTLS(t)
	userAddr, user := serveTestIMAP(t, cfg.IMAP, cert, imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapUIDPlus: {}}, nil)
	cfg.IMAP.Address, cfg.IMAP.CAFile = userAddr, ca
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	server := httptest.NewTLSServer(g)
	defer func() { server.Close() }()
	const query = "types=Email,Mailbox,Thread&closeafter=state&ping=0"
	in := openTestEvents(t, server, cfg.Token, query, "")
	before := readTestEvent(t, bufio.NewReader(in.Body))
	if _, err := io.ReadAll(in.Body); err != nil {
		t.Fatal(err)
	}
	in.Body.Close()
	if before.name != "state" || before.id == "" || before.data["@type"] != "StateChange" {
		t.Fatalf("invalid initial event: %+v", before)
	}
	changed := before.data["changed"].(map[string]any)[cfg.AccountID].(map[string]any)
	if len(changed) != 3 || changed["Thread"] == nil || changed["Email"] == nil || changed["Mailbox"] == nil {
		t.Fatalf("state type filtering failed: %v", changed)
	}
	server.Close()
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	g = reopened
	server = httptest.NewTLSServer(g)
	resumed := openTestEvents(t, server, cfg.Token, "types=Email&closeafter=state&ping=1", before.id)
	defer resumed.Body.Close()
	reader := bufio.NewReader(resumed.Body)
	if ping := readTestEvent(t, reader); ping.name != "ping" || ping.id != "" || ping.data["interval"] != float64(1) {
		t.Fatalf("resume should stay open and ping while Email state is unchanged: %+v", ping)
	}
	if _, err := user.Append("INBOX", strings.NewReader("Subject: External event\r\n\r\nBody\r\n"), &imap.AppendOptions{Time: time.Now()}); err != nil {
		t.Fatal(err)
	}
	var next receivedEvent
	for {
		next = readTestEvent(t, reader)
		if next.name == "state" {
			break
		}
	}
	if next.id == before.id || next.id == "" {
		t.Fatalf("missing new event id: %+v", next)
	}
	delivered := next.data["changed"].(map[string]any)[cfg.AccountID].(map[string]any)
	if len(delivered) != 1 || delivered["Email"] == changed["Email"] {
		t.Fatalf("unexpected state delta: %v", delivered)
	}
	if _, err := reader.ReadByte(); err != io.EOF {
		t.Fatalf("closeafter=state did not end the stream: %v", err)
	}
	delta := gatewayCalls(t, g, cfg.Token, [3]any{"Email/changes", object{"accountId": cfg.AccountID,
		"sinceState": changed["Email"]}, "delta"})[0]
	if delta.Name != "Email/changes" || delta.Args["newState"] != delivered["Email"] || len(delta.Args["created"].([]any)) != 1 {
		t.Fatalf("event state is not usable for changes: %v", delta)
	}
}

func TestEventSourceLimitsAndShutdown(t *testing.T) {
	cfg := testConfig(t)
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	if options, ok := g.eventOptions("types=*&closeafter=no&ping=4000"); !ok ||
		options.ping != 300*time.Second || options.close || len(options.kinds) != 5 {
		t.Fatalf("unexpected wildcard and ping options: %+v", options)
	}
	for _, input := range []string{
		"types=%&closeafter=no&ping=0", "types=,&closeafter=no&ping=0", "types=Email&closeafter=yes&ping=0",
		"types=Email&closeafter=no&ping=-1", "types=Email&types=Mailbox&closeafter=no&ping=0",
		"types=" + strings.Repeat("Email,", 32) + "Mailbox&closeafter=no&ping=0",
	} {
		if _, ok := g.eventOptions(input); ok {
			t.Fatalf("accepted %q", input)
		}
	}
	payload := "broken"
	if states := g.resumeEvents(payload + "." + g.signCursor("event:"+payload)); len(states) != 0 {
		t.Fatalf("accepted malformed cursor: %v", states)
	}
	server := httptest.NewUnstartedServer(g)
	server.EnableHTTP2 = true
	server.StartTLS()
	defer func() { server.Close() }()
	stream := openTestEvents(t, server, cfg.Token, "types=Identity&closeafter=no&ping=1", "")
	defer stream.Body.Close()
	reader := bufio.NewReader(stream.Body)
	if state := readTestEvent(t, reader); stream.ProtoMajor != 2 || state.name != "state" || state.id == "" {
		t.Fatalf("persistent stream did not send initial state: %+v", state)
	}
	if ping := readTestEvent(t, reader); ping.name != "ping" || ping.id != "" {
		t.Fatalf("persistent stream did not send a heartbeat: %+v", ping)
	}
	stream.Body.Close()
	server.Close()
	server = httptest.NewTLSServer(g)
	const query = "types=Unknown&closeafter=no&ping=0"
	responses := make([]*http.Response, 0, maxEventStreams)
	for range maxEventStreams {
		responses = append(responses, openTestEvents(t, server, cfg.Token, query, ""))
	}
	limited := gatewayRequest(g, http.MethodGet, "/events?"+query, cfg.Token, nil)
	if limited.Code != http.StatusServiceUnavailable || limited.Header().Get("Retry-After") == "" {
		t.Fatalf("event stream limit missing: %v", limited)
	}
	denied := gatewayRequest(g, http.MethodGet, "/events?"+query, "invalid", nil)
	if denied.Code != http.StatusUnauthorized {
		t.Fatalf("event authentication missing: %v", denied)
	}
	api := gatewayCalls(t, g, cfg.Token, [3]any{"Core/echo", object{}, "normal"})[0]
	if api.Name != "Core/echo" {
		t.Fatalf("saturated event streams exhausted API admission: %v", api)
	}
	g.StopEvents()
	for _, response := range responses {
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || len(body) != 0 {
			t.Fatalf("shutdown should close quiet stream without ping or state: %q %v", body, err)
		}
	}
}

type noStreamWriter struct{ http.ResponseWriter }

type failingStreamWriter struct{ *httptest.ResponseRecorder }

func (failingStreamWriter) Write([]byte) (int, error) { return 0, errors.New("client disconnected") }

func TestEventSourceUnavailableAndWriteFailures(t *testing.T) {
	cfg, cert := vacationConfig(t)
	listener := listenTCP(t)
	cfg.IMAP.Address = listener.Addr().String()
	_ = listener.Close()
	gate := func(g *Gateway) {
		g.gate <- struct{}{}
		if states := g.eventStates(context.Background(), []string{"Identity"}); len(states) != 0 {
			t.Fatal("event observation should yield while another operation owns the gate")
		}
		<-g.gate
	}
	for _, scenario := range []string{"", "get", "auth"} {
		t.Run(scenario, func(t *testing.T) {
			cfg := cfg
			upstream := *cfg.ManageSieve
			cfg.ManageSieve = &upstream
			cfg.ManageSieve.Address = serveTestSieve(t, cfg.ManageSieve, cert, scenario)
			g, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer g.Close()
			gate(g)
			options, ok := g.eventOptions("types=*&closeafter=no&ping=0")
			if !ok || len(options.kinds) != 6 {
				t.Fatal("optional vacation state is missing from wildcard")
			}
			states := g.eventStates(context.Background(), options.kinds)
			if states["Email"] != "" || states["Identity"] == "" || states["EmailSubmission"] == "" ||
				(states["VacationResponse"] != "") != (scenario == "") {
				t.Fatalf("backend outage affected unrelated types: %v", states)
			}
			req := httptest.NewRequest(http.MethodGet, "https://gateway.example/events?types=Identity&closeafter=no&ping=0", nil)
			g.serveEvents(noStreamWriter{httptest.NewRecorder()}, req)
			g.serveEvents(failingStreamWriter{httptest.NewRecorder()}, req)
			req = httptest.NewRequest(http.MethodGet, "https://gateway.example/events?types=Unknown&closeafter=no&ping=1", nil)
			g.serveEvents(failingStreamWriter{httptest.NewRecorder()}, req)
		})
	}
}

func TestEventSourceCancellationClosesBackendPoll(t *testing.T) {
	cfg := testConfig(t)
	listener := listenTCP(t)
	cfg.IMAP.Address = listener.Addr().String()
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	accepted := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		close(accepted)
		_, _ = io.Copy(io.Discard, conn)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "https://gateway.example/events?types=Email&closeafter=no&ping=0", nil)
	done := make(chan struct{})
	go func() {
		g.serveEvents(httptest.NewRecorder(), req)
		close(done)
	}()
	select {
	case <-accepted:
		cancel()
	case <-ctx.Done():
		t.Fatal("poll did not connect before deadline")
	}
	select {
	case <-done:
		if len(g.gate) != 0 || len(g.eventSlots) != 0 {
			t.Fatal("cancellation left the backend or connection slot locked")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation did not stop backend poll")
	}
}
