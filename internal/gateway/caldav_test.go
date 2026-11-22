package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

const davXMLStart = `<D:multistatus xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">`
const davCalendarType = "<D:resourcetype><D:collection/><C:calendar/></D:resourcetype>"
const davCollectionType = "<D:resourcetype><D:collection/></D:resourcetype>"

func davRow(href, props string, status int) string {
	return fmt.Sprintf("<D:response><D:href>%s</D:href><D:propstat><D:prop>%s</D:prop><D:status>HTTP/1.1 %d Test</D:status></D:propstat></D:response>", href, props, status)
}

func serveCalendarFixture(t *testing.T, additional func(string) string) CalDAVConfig {
	t.Helper()
	cert, ca := testTLS(t)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		login, password, ok := r.BasicAuth()
		if !ok || (login != "first" && login != "second") || password != "fixture-"+login {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		input, err := io.ReadAll(r.Body)
		if err != nil || r.Method != "PROPFIND" || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/xml") {
			t.Error("CalDAV client sent an invalid request")
		}
		var response string
		principal := "/principals/" + login + "/"
		home := "/calendars/" + login + "/"
		switch r.URL.Path {
		case "/dav/":
			if r.Header.Get("Depth") != "0" || !strings.Contains(string(input), "current-user-principal") {
				t.Error("incorrect principal request")
			}
			response = davRow("/other", "", 404) + davRow("/dav/", "<D:current-user-principal><D:href>"+principal+"</D:href></D:current-user-principal>", 200)
		case principal:
			if r.Header.Get("Depth") != "0" || !strings.Contains(string(input), "calendar-home-set") {
				t.Error("incorrect calendar home request")
			}
			response = davRow(principal, "", 404) + davRow(principal, "<C:calendar-home-set><D:href>"+strings.TrimSuffix(home, "/")+"</D:href></C:calendar-home-set>", 200)
		case home:
			if r.Header.Get("Depth") != "1" || !strings.Contains(string(input), "calendar-description") {
				t.Error("incorrect calendar listing request")
			}
			response = davRow(home, davCollectionType, 200) + additional(login)
		default:
			t.Errorf("unexpected target %q", r.URL.Path)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusMultiStatus)
		_, _ = io.WriteString(w, davXMLStart+response+"</D:multistatus>")
	}))
	server.TLS = cert
	server.StartTLS()
	t.Cleanup(server.Close)
	return CalDAVConfig{URL: server.URL + "/dav/", Username: "first", Password: "fixture-first", CAFile: ca}
}

func calendarCall(t *testing.T, g *Gateway, token, method string, args object) object {
	t.Helper()
	payload, err := json.Marshal(object{"using": []string{core, calendarPreview}, "methodCalls": [][3]any{{"Calendar/" + method, args, "cal"}}})
	if err != nil {
		t.Fatal(err)
	}
	response := gatewayRequest(g, http.MethodPost, "/jmap", token, payload)
	var output struct {
		Responses [][3]json.RawMessage `json:"methodResponses"`
	}
	var result object
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &output) != nil || len(output.Responses) != 1 ||
		json.Unmarshal(output.Responses[0][1], &result) != nil {
		t.Fatalf("calendar response %d %s", response.Code, response.Body)
	}
	return result
}

func TestCalendarPreviewAcrossAccountsAndRestart(t *testing.T) {
	var phase atomic.Int32
	dav := serveCalendarFixture(t, func(login string) string {
		if login == "second" {
			return davRow("second-only/", davCalendarType+"<D:displayname>Second</D:displayname>", 200)
		}
		rows := davRow("work/", davCalendarType+"<C:calendar-description>Work notes</C:calendar-description>", 200)
		if phase.Load() == 0 {
			rows += davRow("retired/", davCalendarType, 200)
		} else {
			rows = davRow("work/", davCalendarType+"<D:displayname>Team work</D:displayname>", 200)
			rows += davRow("new/", davCalendarType+"<D:displayname>"+strings.Repeat("ä", 130)+"</D:displayname>", 200)
		}
		return rows + davRow("https://foreign.test/cal/", davCalendarType, 200) +
			davRow("/calendars/second/other/", davCalendarType, 200) +
			davRow("deep/child/", davCalendarType, 200) + davRow("hidden/", davCalendarType, 403) +
			davRow("folder/", davCollectionType, 200)
	})
	cfg := testConfig(t)
	second := dav
	second.Username, second.Password = "second", "fixture-second"
	cfg.CalDAV = &dav
	cfg.AdditionalAccounts = []AccountConfig{
		{AccountID: "second", StateDir: t.TempDir() + "/state", IdentityEmail: "second@example.test", IMAP: cfg.IMAP, SMTP: cfg.SMTP, CalDAV: &second},
		{AccountID: "mail-only", StateDir: t.TempDir() + "/state", IdentityEmail: "mail@example.test", IMAP: cfg.IMAP, SMTP: cfg.SMTP},
	}
	start := func(config Config) *Gateway {
		t.Helper()
		g, err := New(config)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = g.Close() })
		return g
	}
	g := start(cfg)
	res := gatewayRequest(g, http.MethodGet, "/.well-known/jmap", cfg.Token, nil)
	var session object
	if res.Code != 200 || json.Unmarshal(res.Body.Bytes(), &session) != nil {
		t.Fatalf("calendar discovery: %d %s", res.Code, res.Body)
	}
	capabilities := session["capabilities"].(map[string]any)
	if capabilities[calendarPreview] == nil || capabilities["urn:ietf:params:jmap:calendars"] != nil ||
		session["primaryAccounts"].(map[string]any)[calendarPreview] != cfg.AccountID {
		t.Fatalf("calendar capabilities: %v", session)
	}
	root := func() object { return object{"accountId": cfg.AccountID} }
	first := calendarCall(t, g, cfg.Token, "get", root())
	calendars := first["list"].([]any)
	if len(calendars) != 2 {
		t.Fatalf("wrong calendar result: %v", first)
	}
	var workID string
	for _, raw := range calendars {
		entry := raw.(map[string]any)
		if entry["name"] == "work" && entry["description"] == "Work notes" {
			workID = entry["id"].(string)
		}
	}
	if workID == "" {
		t.Fatal("missing fallback name and description")
	}
	child := calendarCall(t, g, cfg.Token, "get", object{"accountId": "second"})
	if list := child["list"].([]any); len(list) != 1 || list[0].(map[string]any)["name"] != "Second" {
		t.Fatalf("wrong secondary calendars: %v", child)
	}
	child = calendarCall(t, g, cfg.Token, "get", object{"accountId": "second", "ids": []string{workID}})
	if len(child["notFound"].([]any)) != 1 {
		t.Fatalf("calendar was visible in the wrong account: %v", child)
	}
	for _, test := range []struct {
		method string
		args   object
		want   string
	}{
		{"get", object{"accountId": "mail-only"}, "accountNotSupportedByMethod"},
		{"set", root(), "unknownMethod"},
		{"get", object{"accountId": cfg.AccountID, "fetchTextBodyValues": true}, "invalidArguments"},
		{"get", object{"accountId": cfg.AccountID, "properties": []string{"myRights"}}, "invalidArguments"},
	} {
		if got := calendarCall(t, g, cfg.Token, test.method, test.args); got["type"] != test.want {
			t.Fatalf("calendar %s: want %s, got %v", test.method, test.want, got)
		}
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	phase.Store(1)
	g = start(cfg)
	changes := calendarCall(t, g, cfg.Token, "changes", object{"accountId": cfg.AccountID, "sinceState": first["state"]})
	if len(changes["created"].([]any)) != 1 || len(changes["destroyed"].([]any)) != 1 ||
		len(changes["updated"].([]any)) != 1 || changes["updated"].([]any)[0] != workID ||
		changes["hasMoreChanges"] != false {
		t.Fatalf("changes not retained across restart: %v", changes)
	}
	got := calendarCall(t, g, cfg.Token, "get", object{"accountId": cfg.AccountID,
		"ids": []string{workID, changes["created"].([]any)[0].(string)}, "properties": []string{"name"}})
	list := got["list"].([]any)
	if len(list) != 2 || len(list[0].(map[string]any)) != 2 || list[0].(map[string]any)["name"] != "Team work" ||
		len(list[1].(map[string]any)["name"].(string)) != 254 || got["state"] != changes["newState"] {
		t.Fatalf("incorrect get result after restart: %v", got)
	}
}

func TestCalendarPreviewBoundsAndFailure(t *testing.T) {
	dav := serveCalendarFixture(t, func(string) string {
		var entries strings.Builder
		for i := range maxGet + 1 {
			entries.WriteString(davRow(fmt.Sprintf("calendar-%d/", i), davCalendarType, 200))
		}
		return entries.String()
	})
	cfg := testConfig(t)
	cfg.CalDAV = &dav
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	args := object{"accountId": cfg.AccountID}
	if got := calendarCall(t, g, cfg.Token, "get", args); got["type"] != "requestTooLarge" {
		t.Fatalf("unbounded get: %v", got)
	}
	cfg.CalDAV.Password = "wrong-password"
	cfg.StateDir = t.TempDir() + "/state"
	bad, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	for _, method := range []string{"get", "changes"} {
		args := object{"accountId": cfg.AccountID}
		if method == "changes" {
			args["sinceState"] = "previous"
		}
		if got := calendarCall(t, bad, cfg.Token, method, args); got["type"] != "serverUnavailable" {
			t.Fatalf("upstream authentication failure: %v", got)
		}
	}
	for _, config := range []*CalDAVConfig{
		{URL: "https://user:pass@example.test/dav", Username: "user", Password: "pass"},
		{URL: "http://example.test/dav", Username: "user", Password: "pass"},
		{URL: "https://example.test", Username: "user:spoof", Password: "pass"},
		{URL: "https://example.test", Username: "user", Password: "pass", CAFile: t.TempDir() + "/missing"},
	} {
		cfg.CalDAV = config
		if broken, err := New(cfg); err == nil {
			_ = broken.Close()
			t.Fatal("invalid CalDAV configuration accepted")
		}
	}
}

func TestCalDAVRefusesUntrustedTransportAndResponses(t *testing.T) {
	cert, ca := testTLS(t)
	var phase atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/trap" {
			t.Error("CalDAV client followed a redirect")
		}
		switch phase.Load() {
		case 0:
			http.Redirect(w, r, "/trap", http.StatusTemporaryRedirect)
		case 1:
			w.WriteHeader(http.StatusMultiStatus)
			_, _ = io.WriteString(w, davXMLStart+strings.Repeat("x", maxDAVResponse))
		case 2:
			w.WriteHeader(http.StatusMultiStatus)
			_, _ = io.WriteString(w, "<broken")
		case 3:
			w.WriteHeader(http.StatusMultiStatus)
			_, _ = io.WriteString(w, davXMLStart+davRow("/", "<D:current-user-principal><D:href>https://foreign.test/</D:href></D:current-user-principal>", 200)+"</D:multistatus>")
		case 4, 7:
			if phase.Load() == 7 && r.URL.Path == "/home/" {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusMultiStatus)
			row := ""
			switch r.URL.Path {
			case "/":
				row = davRow("/", "<D:current-user-principal><D:href>/principal/</D:href></D:current-user-principal>", 200)
			case "/principal/":
				row = davRow("/principal/", "<C:calendar-home-set><D:href>/home/</D:href></C:calendar-home-set>", 200)
			case "/home/":
				row = davRow("/home/", "", 403)
			}
			_, _ = io.WriteString(w, davXMLStart+row+"</D:multistatus>")
		case 5:
			w.Header().Set("Content-Length", "2000")
			w.WriteHeader(http.StatusMultiStatus)
			_, _ = io.WriteString(w, davXMLStart)
		case 6:
			if r.URL.Path == "/principal/" {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusMultiStatus)
			_, _ = io.WriteString(w, davXMLStart+davRow("/", "<D:current-user-principal><D:href>/principal/</D:href></D:current-user-principal>", 200)+"</D:multistatus>")
		}
	}))
	server.TLS = cert
	server.StartTLS()
	t.Cleanup(server.Close)
	config := &CalDAVConfig{URL: server.URL, Username: "user", Password: "pass"}
	dav, err := newCalDAV(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, failure := dav.calendars(context.Background(), "a"); failure != "serverUnavailable" {
		t.Fatal("unexpected acceptance of untrusted TLS certificate")
	}
	config.CAFile = ca
	dav, err = newCalDAV(config)
	if err != nil {
		t.Fatal(err)
	}
	for i := range int32(8) {
		phase.Store(i)
		if _, failure := dav.calendars(context.Background(), "a"); failure != "serverUnavailable" {
			t.Fatalf("invalid CalDAV response accepted in phase %d", i)
		}
	}
	if _, failure := dav.propfind(context.Background(), &url.URL{Scheme: "https", Host: "bad host"}, "0", ""); failure != "serverUnavailable" {
		t.Fatal("invalid PROPFIND target accepted")
	}
	for _, href := range []string{"%xx", "../other", "/cal%2fsecret", " ", "//a@b/", "/cal?x=y"} {
		if dav.resolve(dav.base, href) != nil {
			t.Fatalf("unsafe href %q accepted", href)
		}
	}
}
