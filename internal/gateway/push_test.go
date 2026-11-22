package gateway

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type pushDelivery struct {
	Path, TTL, Encoding, ContentType string
	Body                             []byte
}

func testPushReceiver(t *testing.T, cfg *Config) (*httptest.Server, <-chan pushDelivery) {
	t.Helper()
	deliveries := make(chan pushDelivery, 16)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, err := io.ReadAll(r.Body)
		if err != nil || r.Method != http.MethodPost || r.Header.Get("Authorization") != "" {
			t.Errorf("invalid upstream push request")
		}
		deliveries <- pushDelivery{r.URL.Path, r.Header.Get("TTL"), r.Header.Get("Content-Encoding"), r.Header.Get("Content-Type"), payload}
		switch r.URL.Path {
		case "/slow":
			w.Header().Set("Retry-After", "120")
			w.WriteHeader(http.StatusTooManyRequests)
		case "/gone":
			w.WriteHeader(http.StatusGone)
		case "/redirect":
			http.Redirect(w, r, "/must-not-follow", http.StatusTemporaryRedirect)
		default:
			w.WriteHeader(http.StatusCreated)
		}
	}))
	t.Cleanup(server.Close)
	cfg.PushOrigins = []string{server.URL}
	cfg.PushCAFile = filepath.Join(t.TempDir(), "push.pem")
	if err := os.WriteFile(cfg.PushCAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	return server, deliveries
}

func receivePush(t *testing.T, deliveries <-chan pushDelivery) pushDelivery {
	t.Helper()
	select {
	case data := <-deliveries:
		if data.TTL != "60" || data.ContentType != "application/json" {
			t.Fatalf("bad push headers: %+v", data)
		}
		return data
	case <-time.After(6 * time.Second):
		t.Fatal("missing HTTPS push")
	}
	return pushDelivery{}
}

func pushTestAPI(t *testing.T, g *Gateway, cfg Config, method string, args object) object {
	t.Helper()
	response := gatewayCalls(t, g, cfg.Token, [3]any{"PushSubscription/" + method, args, "push"})[0]
	return response.Args
}

func testPushAssignment(t *testing.T, result object, field, key string) object {
	t.Helper()
	entries, ok := result[field].(map[string]any)
	if !ok {
		t.Fatalf("missing %s: %v", field, result)
	}
	value, ok := entries[key].(map[string]any)
	if !ok {
		t.Fatalf("missing %s entry %q: %v", field, key, result)
	}
	return value
}

func openTestPush(t *testing.T, wire []byte, receiver *ecdh.PrivateKey, auth []byte) object {
	t.Helper()
	var result object
	if receiver != nil {
		if len(wire) < 103 || wire[20] != 65 {
			t.Fatal("invalid Web Push record")
		}
		sender, err := ecdh.P256().NewPublicKey(wire[21:86])
		if err != nil {
			t.Fatal(err)
		}
		secret, err := receiver.ECDH(sender)
		if err != nil {
			t.Fatal(err)
		}
		contextInfo := "WebPush: info\x00" + string(receiver.PublicKey().Bytes()) + string(sender.Bytes())
		input, _ := hkdf.Key(sha256.New, secret, auth, contextInfo, 32)
		key, _ := hkdf.Key(sha256.New, input, wire[:16], "Content-Encoding: aes128gcm\x00", 16)
		nonce, _ := hkdf.Key(sha256.New, input, wire[:16], "Content-Encoding: nonce\x00", 12)
		block, _ := aes.NewCipher(key)
		aead, _ := cipher.NewGCM(block)
		plain, err := aead.Open(nil, nonce, wire[86:], nil)
		if err != nil || len(plain) == 0 || plain[len(plain)-1] != 2 {
			t.Fatal("cannot authenticate encrypted push")
		}
		wire = plain[:len(plain)-1]
	}
	if err := json.Unmarshal(wire, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestPushSubscriptionOverTLS(t *testing.T) {
	cfg := testConfig(t)
	server, deliveries := testPushReceiver(t, &cfg)
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	browser, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth := bytes.Repeat([]byte{0x96}, 16)
	keys := pushKeys{base64.RawURLEncoding.EncodeToString(browser.PublicKey().Bytes()), base64.RawURLEncoding.EncodeToString(auth)}
	created := pushTestAPI(t, g, cfg, "set", object{"create": object{"device": object{
		"deviceClientId": "opaque-device", "url": server.URL + "/deliver?secret=kept", "types": []string{"Identity"}, "keys": keys,
	}}})
	id := testPushAssignment(t, created, "created", "device")["id"].(string)
	first := receivePush(t, deliveries)
	verify := openTestPush(t, first.Body, browser, auth)
	if first.Encoding != "aes128gcm" || verify["@type"] != "PushVerification" ||
		verify["pushSubscriptionId"] != id || verify["verificationCode"] == "" || created["newState"] != nil {
		t.Fatalf("bad verification: %v", verify)
	}
	get := pushTestAPI(t, g, cfg, "get", object{"ids": []string{"missing", id, id, "missing"}})
	entry := get["list"].([]any)[0].(map[string]any)
	if len(get["list"].([]any)) != 1 || len(entry) != 5 || entry["id"] != id || entry["verificationCode"] != nil || get["accountId"] != nil ||
		!reflect.DeepEqual(get["notFound"], []any{"missing"}) {
		t.Fatalf("wrong public subscription: %v", get)
	}
	if response := pushTestAPI(t, g, cfg, "get", object{"accountId": cfg.AccountID}); response["type"] != "invalidArguments" {
		t.Fatalf("account argument allowed on PushSubscription/get: %v", response)
	}
	if forbidden := pushTestAPI(t, g, cfg, "get", object{"properties": []string{"url"}}); forbidden["type"] != "forbidden" {
		t.Fatalf("private URL exposed: %v", forbidden)
	}
	bad := pushTestAPI(t, g, cfg, "set", object{"update": object{id: object{"verificationCode": "wrong", "types": []string{"Email"}}}})
	if failure := testPushAssignment(t, bad, "notUpdated", id); failure["type"] != "invalidProperties" {
		t.Fatalf("invalid code accepted: %v", bad)
	}
	g.pollPush(context.Background())
	select {
	case delivery := <-deliveries:
		t.Fatalf("unverified delivery: %+v", delivery)
	default:
	}
	accepted := pushTestAPI(t, g, cfg, "set", object{"update": object{id: object{"verificationCode": verify["verificationCode"]}}})
	if accepted["updated"] == nil {
		t.Fatalf("correct verification failed: %v", accepted)
	}
	verified := pushTestAPI(t, g, cfg, "get", object{"ids": []string{id}})["list"].([]any)[0].(map[string]any)
	if verified["verificationCode"] != verify["verificationCode"] {
		t.Fatal("confirmed verification code missing")
	}
	state := openTestPush(t, receivePush(t, deliveries).Body, browser, auth)
	changed := state["changed"].(map[string]any)[cfg.AccountID].(map[string]any)
	if state["@type"] != "StateChange" || len(changed) != 1 || changed["Identity"] == nil {
		t.Fatalf("wrong pushed types: %v", state)
	}
	g.push.mu.Lock()
	acknowledged := g.push.records[id].Last["Identity"]
	g.push.mu.Unlock()
	if acknowledged != changed["Identity"] {
		t.Fatal("receiver acknowledgement did not persist")
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	cfg.IdentityName = "Changed after restart"
	reopened, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	g = reopened
	after := openTestPush(t, receivePush(t, deliveries).Body, browser, auth)
	if after["changed"].(map[string]any)[cfg.AccountID].(map[string]any)["Identity"] == changed["Identity"] {
		t.Fatalf("reopened subscription did not observe new state: %v", after)
	}
	destroy := pushTestAPI(t, g, cfg, "set", object{"destroy": []string{"missing", id}})
	if !reflect.DeepEqual(destroy["destroyed"], []any{id}) ||
		testPushAssignment(t, destroy, "notDestroyed", "missing")["type"] != "notFound" {
		t.Fatalf("bad destruction: %v", destroy)
	}
	raw, err := os.ReadFile(filepath.Join(cfg.StateDir, pushFile))
	if err != nil || bytes.Contains(raw, []byte("secret=kept")) || bytes.Contains(raw, []byte(keys.Public)) {
		t.Fatalf("destroyed private material remained in the store")
	}
}

type cancelPushTransport struct{ cancel context.CancelFunc }

func (transport cancelPushTransport) RoundTrip(*http.Request) (*http.Response, error) {
	transport.cancel()
	return nil, context.Canceled
}

func TestPushShutdownDoesNotDelayRetry(t *testing.T) {
	const origin = "https://push.example.test"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := &pushStore{
		origins: map[string]bool{origin: true},
		records: map[string]pushSubscription{"active": {URL: origin, Verified: true, Expires: time.Now().Add(time.Hour)}},
		client:  &http.Client{Transport: cancelPushTransport{cancel}},
	}
	store.deliverPush(ctx, "active", "account", map[string]map[string]string{"account": {"Identity": "change"}})
	if !store.records["active"].RetryAt.IsZero() || store.failed {
		t.Fatal("shutdown poisoned the original subscription")
	}
}

func TestPushWebEncryptionRFC8291(t *testing.T) {
	b64 := base64.RawURLEncoding
	decode := func(data string) []byte {
		t.Helper()
		raw, err := b64.DecodeString(data)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	sender, err := ecdh.P256().NewPrivateKey(decode("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"))
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := ecdh.P256().NewPublicKey(decode("BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"))
	if err != nil {
		t.Fatal(err)
	}
	auth := decode("BTBZMqHH6r4Tts7J_aSIgg")
	salt := decode("DGv6ra1nlYgDCS1FRnbzlw")
	payload, err := sealPush([]byte("When I grow up, I want to be a watermelon"), receiver, auth, sender, salt)
	expected := "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml" +
		"mlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPT" +
		"pK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"
	if err != nil || b64.EncodeToString(payload) != expected {
		t.Fatalf("published Web Push vector mismatch: %v", err)
	}
	other, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sealPush(nil, other.PublicKey(), auth, sender, salt); err == nil {
		t.Fatal("wrong ECDH curve succeeded")
	}
	if _, err := encryptPush([]byte(strings.Repeat("x", pushRecordSize)), &pushKeys{b64.EncodeToString(receiver.Bytes()), b64.EncodeToString(auth)}); err == nil {
		t.Fatal("oversize push accepted")
	}
}

func TestPushValidationAndStatePolicy(t *testing.T) {
	cfg := testConfig(t)
	server, deliveries := testPushReceiver(t, &cfg)
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	// Drive retries explicitly so these assertions do not depend on tick timing.
	g.push.stop()
	valid := object{"deviceClientId": "fixture", "url": server.URL + "/redirect"}
	for _, test := range []struct {
		name  string
		input any
		code  string
	}{
		{"shape", []any{}, "invalidProperties"},
		{"id", object{"deviceClientId": "", "url": server.URL}, "invalidProperties"},
		{"scheme", object{"deviceClientId": "id", "url": "http://127.0.0.1"}, "invalidProperties"},
		{"origin", object{"deviceClientId": "id", "url": "https://outside.invalid"}, "forbidden"},
		{"code", object{"deviceClientId": "id", "url": server.URL, "verificationCode": "notnull"}, "invalidProperties"},
		{"keys", object{"deviceClientId": "id", "url": server.URL, "keys": object{"auth": "bad", "p256dh": "bad"}}, "invalidProperties"},
		{"date", object{"deviceClientId": "id", "url": server.URL, "expires": "2020-01-01T00:00:00Z"}, "invalidProperties"},
		{"types", object{"deviceClientId": "id", "url": server.URL, "types": []string{""}}, "invalidProperties"},
		{"type limit", object{"deviceClientId": "id", "url": server.URL, "types": make([]string, 33)}, "invalidProperties"},
	} {
		got := pushTestAPI(t, g, cfg, "set", object{"create": object{"test": test.input}})
		if failure := testPushAssignment(t, got, "notCreated", "test"); failure["type"] != test.code {
			t.Fatalf("%s: %v", test.name, got)
		}
	}
	for _, test := range []struct {
		method, code string
		input        object
	}{
		{"get", "invalidArguments", object{"accountId": cfg.AccountID}},
		{"get", "requestTooLarge", object{"ids": make([]string, maxGet+1)}},
		{"get", "invalidArguments", object{"properties": []string{"unknown"}}},
		{"set", "invalidArguments", object{"ifInState": "invalid"}},
		{"set", "requestTooLarge", object{"destroy": make([]string, maxSet+1)}},
		{"set", "invalidArguments", object{"create": object{"#invalid": valid}}},
	} {
		if result := pushTestAPI(t, g, cfg, test.method, test.input); result["type"] != test.code {
			t.Fatalf("got %v, want %s", result, test.code)
		}
	}
	flow := gatewayCalls(t, g, cfg.Token,
		[3]any{"PushSubscription/set", object{"create": object{"new": valid}, "update": object{"#new": object{"types": []string{"Email"}}}}, "create"},
		[3]any{"PushSubscription/get", object{"ids": []string{"#new"}, "properties": []string{"types"}}, "get"})
	id := testPushAssignment(t, flow[0].Args, "created", "new")["id"].(string)
	if flow[0].Args["updated"] == nil || flow[1].Args["list"].([]any)[0].(map[string]any)["id"] != id {
		t.Fatalf("creation reference failed: %v", flow)
	}
	upstream := receivePush(t, deliveries)
	if upstream.Path != "/redirect" || upstream.Encoding != "" || len(deliveries) != 0 {
		t.Fatalf("client followed redirect or sent unexpected content encoding: %+v", upstream)
	}
	if get := pushTestAPI(t, g, cfg, "get", object{}); len(get["list"].([]any)) != 1 {
		t.Fatalf("pending subscription was not retained: %v", get)
	}
	if result := pushTestAPI(t, g, cfg, "set", object{"update": object{"unknown": object{}}}); testPushAssignment(t, result, "notUpdated", "unknown")["type"] != "notFound" {
		t.Fatalf("bad unknown update: %v", result)
	}
	for _, patch := range []any{nil, object{"verificationCode": true}, object{"expires": true},
		object{"expires": "2020-01-01T00:00:00Z"}, object{"types": []string{""}}, object{"url": server.URL},
		object{"keys": object{}}, object{"other": "value"}} {
		if result := pushTestAPI(t, g, cfg, "set", object{"update": object{id: patch}}); result["notUpdated"] == nil {
			t.Fatalf("bad patch accepted: %v", patch)
		}
	}
	extended := time.Now().Add(20 * 24 * time.Hour).UTC().Format(time.RFC3339)
	if result := pushTestAPI(t, g, cfg, "set", object{"update": object{id: object{"id": id, "verificationCode": nil,
		"keys": nil, "expires": extended, "deviceClientId": "fixture", "url": server.URL + "/redirect"}}}); result["updated"] == nil {
		t.Fatalf("valid update: %v", result)
	}

	g.push.mu.Lock()
	g.push.verifies = append([]time.Time{time.Now().Add(-time.Hour)}, make([]time.Time, maxPushVerifies)...)
	for i := 1; i < len(g.push.verifies); i++ {
		g.push.verifies[i] = time.Now()
	}
	g.push.mu.Unlock()
	if result := pushTestAPI(t, g, cfg, "set", object{"create": object{"limited": valid}}); testPushAssignment(t, result, "notCreated", "limited")["type"] != "rateLimit" {
		t.Fatalf("missing verification limit: %v", result)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	cfg.Token = strings.Repeat("z", 32)
	reopened, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	g = reopened
	if get := pushTestAPI(t, g, cfg, "get", object{}); len(get["list"].([]any)) != 0 {
		t.Fatalf("rotated credentials retained subscriptions: %v", get)
	}
}

func TestPushRetryAndTransportPolicy(t *testing.T) {
	cfg := testConfig(t)
	server, deliveries := testPushReceiver(t, &cfg)
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	g.push.stop()
	ctx := context.Background()
	p := g.push
	now := time.Now()
	sub := pushSubscription{Expires: now.Add(time.Hour), Types: []string{"Identity"}, Verified: true, URL: server.URL + "/slow"}
	p.records["sample"] = sub
	states := map[string]map[string]string{cfg.AccountID: {"Identity": "known"}}
	p.deliverPush(ctx, "sample", cfg.AccountID, map[string]map[string]string{cfg.AccountID: {"Email": "excluded"}})
	if len(deliveries) != 0 {
		t.Fatal("filtered type triggered delivery")
	}
	p.deliverPush(ctx, "sample", cfg.AccountID, states)
	receivePush(t, deliveries)
	if p.records["sample"].RetryAt.Before(now.Add(120*time.Second)) || p.records["sample"].Last["Identity"] != "" {
		t.Fatal("429 must delay retry without acknowledging state")
	}
	p.deliverPush(ctx, "sample", cfg.AccountID, states)
	if len(deliveries) != 0 {
		t.Fatal("429 subscriber was contacted during backoff")
	}
	sub.URL = server.URL + "/gone"
	p.records["sample"] = sub
	p.deliverPush(ctx, "sample", cfg.AccountID, states)
	receivePush(t, deliveries)
	if _, ok := p.records["sample"]; ok {
		t.Fatal("gone endpoint was not erased")
	}
	sub.Expires = now.Add(-time.Second)
	if status, _ := p.post(ctx, sub, object{}); status != 0 {
		t.Fatal("sent to expired subscription")
	}
	p.records["expired"] = sub
	if err := p.prune(now); err != nil || len(p.records) != 0 {
		t.Fatal("expired subscription was not pruned")
	}
	if got := pushRetry(now, "soon"); !got.Equal(now.Add(15 * time.Second)) {
		t.Fatalf("bad minimum retry: %s", got)
	}
	later := now.Add(time.Hour).UTC().Truncate(time.Second)
	if got := pushRetry(now, later.Format(http.TimeFormat)); !got.Equal(later) {
		t.Fatalf("date Retry-After ignored: %s", got)
	}
	sub.Expires = now.Add(time.Minute)
	sub.Keys = &pushKeys{}
	if status, _ := p.post(ctx, sub, object{}); status != 0 {
		t.Fatal("invalid keys sent unencrypted")
	}
	sub.Keys = nil
	server.Close()
	if status, _ := p.post(ctx, sub, object{}); status != 0 {
		t.Fatal("closure did not report a failed push")
	}
}

func TestPushStorageFailuresAndQuota(t *testing.T) {
	cfg := testConfig(t)
	cfg.PushOrigins = []string{"https://invalid.example/path"}
	if _, err := New(cfg); err == nil {
		t.Fatal("accepted an origin with a path")
	}
	server, deliveries := testPushReceiver(t, &cfg)
	cafile := cfg.PushCAFile
	cfg.PushCAFile = "/missing/push/ca"
	if _, err := New(cfg); err == nil {
		t.Fatal("accepted an unreadable TLS CA")
	}
	cfg.PushCAFile = cafile
	path := filepath.Join(cfg.StateDir, pushFile)
	if err := os.Symlink(pushFile, path); err != nil {
		t.Fatal(err)
	}
	if _, err := New(cfg); err == nil || err.Error() != "cannot open push state" {
		t.Fatalf("unreadable state: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(cfg); err == nil || err.Error() != "invalid push state" {
		t.Fatalf("corrupt state: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	g.push.stop()
	for i := range maxPushRecords {
		g.push.records[string(rune('a'+i))] = pushSubscription{Expires: time.Now().Add(time.Hour), URL: server.URL}
	}
	input := object{"create": object{"device": object{"deviceClientId": "quota", "url": server.URL}}}
	if reply := pushTestAPI(t, g, cfg, "set", input); testPushAssignment(t, reply, "notCreated", "device")["type"] != "overQuota" {
		t.Fatalf("quota failure: %v", reply)
	}
	clear(g.push.records)
	g.push.files.rename = func(string, string) error { return diskError }
	reply := pushTestAPI(t, g, cfg, "set", input)
	if reply["type"] != "serverFail" || len(deliveries) != 0 || len(g.push.records) != 0 {
		t.Fatalf("uncommitted subscription sent verification: %v", reply)
	}
	if reply := pushTestAPI(t, g, cfg, "get", object{}); reply["type"] != "serverFail" {
		t.Fatalf("failed store did not fail subsequent calls: %v", reply)
	}
	g.pollPush(context.Background())
	g.push.deliverPush(context.Background(), "device", cfg.AccountID, map[string]map[string]string{cfg.AccountID: {"Identity": "bad"}})
	if len(deliveries) != 0 {
		t.Fatal("failed store sent background notifications")
	}
}
