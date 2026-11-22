package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
)

func twoAccountConfig(t *testing.T, vacation bool) (Config, *imapmemserver.User) {
	t.Helper()
	root, extra := testConfig(t), testConfig(t)
	cert, ca := testTLS(t)
	caps := imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapUIDPlus: {}}
	source, user := serveTestIMAP(t, root.IMAP, cert, caps, nil)
	root.IMAP.Address, root.IMAP.CAFile = source, ca
	extra.IMAP.Username, extra.IMAP.Password = "other-user", "other-fixture"
	extra.IMAP.Address, _ = serveTestIMAP(t, extra.IMAP, cert, caps, nil)
	extra.IMAP.CAFile = ca
	child := AccountConfig{AccountID: "other", IdentityEmail: "other@example.test", IdentityName: "Other",
		StateDir: extra.StateDir, IMAP: extra.IMAP, SMTP: extra.SMTP}
	if vacation {
		child.ManageSieve = &Upstream{Mode: "starttls", Username: "other", Password: "fixture", CAFile: ca}
		child.ManageSieve.Address = serveTestSieve(t, child.ManageSieve, cert, "")
	}
	root.AdditionalAccounts = []AccountConfig{child}
	return root, user
}

func TestAccountRoutingAndBlobCopy(t *testing.T) {
	cfg, user := twoAccountConfig(t, true)
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	const child = "other"
	if g.session["primaryAccounts"].(object)[mailCapability] != cfg.AccountID ||
		g.session["primaryAccounts"].(object)[vacationCapability] != child ||
		len(g.session["accounts"].(object)) != 2 {
		t.Fatalf("inconsistent session accounts: %v", g.session)
	}
	denied := gatewayRequest(g, http.MethodGet, "/.well-known/jmap", strings.Repeat("q", 40), nil)
	if denied.Code != http.StatusUnauthorized {
		t.Fatalf("another bearer accessed the multi-account session: %d", denied.Code)
	}
	sourceBytes := []byte{0, 1, 255, 13, 10}
	upload := func(account string, payload []byte) string {
		t.Helper()
		res := gatewayRequest(g, http.MethodPost, "/upload/"+account, cfg.Token, payload)
		var data object
		if res.Code != 201 || json.Unmarshal(res.Body.Bytes(), &data) != nil || data["accountId"] != account {
			t.Fatalf("upload on %s: %d %s", account, res.Code, res.Body)
		}
		return data["blobId"].(string)
	}
	sourceID := upload(cfg.AccountID, sourceBytes)
	otherID := upload(child, []byte("private other data"))
	download := func(account, blob string, status int, expected []byte) {
		t.Helper()
		response := gatewayRequest(g, http.MethodGet, "/download/"+account+"/"+blob+"/data.bin", cfg.Token, nil)
		if response.Code != status || expected != nil && !bytes.Equal(response.Body.Bytes(), expected) {
			t.Fatalf("download %s returned %d with %q", account, response.Code, response.Body.Bytes())
		}
	}
	download(child, sourceID, 404, nil)
	download(cfg.AccountID, otherID, 404, nil)
	download("unconfigured", sourceID, 404, nil)
	if response := gatewayRequest(g, http.MethodGet, "/download/"+child+"/short", cfg.Token, nil); response.Code != 404 {
		t.Fatalf("malformed download returned %d", response.Code)
	}
	if response := gatewayRequest(g, http.MethodPost, "/upload/unconfigured", cfg.Token, sourceBytes); response.Code != 404 {
		t.Fatalf("unconfigured upload returned %d", response.Code)
	}
	raw := "Subject: Source\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nSaved body\r\n"
	added, err := user.Append("INBOX", strings.NewReader(raw), &imap.AppendOptions{Time: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	saved := emailID(mailboxID(cfg.AccountID, "INBOX"), added.UIDValidity, added.UID)
	messageBlob := "b-" + saved[2:]
	partBlob := partBlobID(saved, "1")
	flow := gatewayCalls(t, g, cfg.Token,
		[3]any{"Blob/copy", object{"accountId": child, "fromAccountId": cfg.AccountID,
			"blobIds": []string{sourceID, messageBlob, partBlob, sourceID, otherID, "-"}}, "copy"},
		[3]any{"Identity/get", object{"accountId": child}, "identity"},
		[3]any{"Identity/get", object{"accountId": "unconfigured"}, "forbidden"})
	result := flow[0].Args
	if flow[0].Name != "Blob/copy" || result["accountId"] != child || result["fromAccountId"] != cfg.AccountID {
		t.Fatalf("bad copy response: %v", flow)
	}
	copied := result["copied"].(map[string]any)
	for _, id := range []string{otherID, "-"} {
		if result["notCopied"].(map[string]any)[id].(map[string]any)["type"] != "notFound" {
			t.Fatalf("unexpected result for %s: %v", id, result)
		}
	}
	download(child, copied[sourceID].(string), 200, sourceBytes)
	download(child, copied[messageBlob].(string), 200, []byte(raw))
	download(child, copied[partBlob].(string), 200, []byte("Saved body\r\n"))
	if flow[1].Args["list"].([]any)[0].(map[string]any)["email"] != "other@example.test" ||
		flow[2].Args["type"] != "accountNotFound" {
		t.Fatalf("account routing: %v", flow)
	}
	ok, result := vacationCall(t, g, cfg, "get", object{"accountId": child})
	if ok != "VacationResponse/get" || result["accountId"] != child {
		t.Fatalf("optional child capability not usable: %v", result)
	}
	if _, result := vacationCall(t, g, cfg, "get", object{}); result["type"] != "accountNotSupportedByMethod" {
		t.Fatalf("unsupported primary capability returned %v", result)
	}
	server := httptest.NewTLSServer(g)
	defer server.Close()
	stream := openTestEvents(t, server, cfg.Token, "types=Identity,VacationResponse&closeafter=state&ping=0", "")
	defer stream.Body.Close()
	event := readTestEvent(t, bufio.NewReader(stream.Body))
	changed := event.data["changed"].(map[string]any)
	if len(changed) != 2 || changed[cfg.AccountID].(map[string]any)["VacationResponse"] != nil ||
		changed[child].(map[string]any)["VacationResponse"] == nil ||
		g.resumeEvents(event.id)[child+"/Identity"] == "" {
		t.Fatalf("unexpected multi-account notification: %v", changed)
	}
}

func TestEmailCopyAndConditionalOriginalRemoval(t *testing.T) {
	cfg, user := twoAccountConfig(t, false)
	const child = "other"
	original := "From: sample@example.test\r\nSubject: Copy this\r\n\r\nOriginal\r\n"
	at := time.Date(2026, 11, 22, 9, 12, 0, 0, time.UTC)
	added, err := user.Append("INBOX", strings.NewReader(original), &imap.AppendOptions{Flags: []imap.Flag{imap.FlagAnswered}, Time: at})
	if err != nil {
		t.Fatal(err)
	}
	source := emailID(mailboxID(cfg.AccountID, "INBOX"), added.UIDValidity, added.UID)
	destination := mailboxID(child, "INBOX")
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	initial := gatewayCalls(t, g, cfg.Token,
		[3]any{"Email/get", object{"accountId": cfg.AccountID, "ids": []string{source}}, "source"},
		[3]any{"Email/get", object{"accountId": child, "ids": []string{source}}, "wrong"})
	if len(initial[1].Args["notFound"].([]any)) != 1 {
		t.Fatalf("source ID read from another account: %v", initial)
	}
	args := object{"fromAccountId": cfg.AccountID, "accountId": child, "ifFromInState": initial[0].Args["state"],
		"ifInState": initial[1].Args["state"], "create": object{
			"copy": object{"id": source, "mailboxIds": object{destination: true}, "keywords": object{"$seen": true},
				"receivedAt": "2026-11-24T10:12:00Z"},
			"missing": object{"id": "missing"},
		}, "onSuccessDestroyOriginal": true, "destroyFromIfInState": "stale"}
	flow := emailActionCalls(t, g, cfg.Token, [3]any{"Email/copy", args, "copy"},
		[3]any{"Email/get", object{"accountId": child, "ids": []string{"#copy"}}, "read"})
	if len(flow) != 3 || flow[0].Name != "Email/copy" || flow[1].Name != "error" ||
		flow[1].Tag != "copy" || flow[1].Args["type"] != "stateMismatch" || flow[2].Name != "Email/get" {
		t.Fatalf("unexpected copy/conditional delete response: %v", flow)
	}
	created := flow[0].Args["created"].(map[string]any)["copy"].(map[string]any)
	entry := flow[2].Args["list"].([]any)[0].(map[string]any)
	keywords := entry["keywords"].(map[string]any)
	if created["id"] == source || len(keywords) != 1 || keywords["$seen"] != true ||
		entry["receivedAt"] != "2026-11-24T10:12:00Z" || int(created["size"].(float64)) != len(original) {
		t.Fatalf("wrong copied data: %v", entry)
	}
	response := gatewayRequest(g, http.MethodGet, "/download/"+child+"/"+created["blobId"].(string)+"/copy.eml", cfg.Token, nil)
	if response.Code != 200 || response.Body.String() != original {
		t.Fatalf("stored copy changed message bytes: %d %q", response.Code, response.Body.String())
	}
	sourceRead := gatewayCalls(t, g, cfg.Token,
		[3]any{"Email/get", object{"accountId": cfg.AccountID, "ids": []string{source}}, "original"})[0]
	if sourceRead.Args["state"] != initial[0].Args["state"] ||
		sourceRead.Args["list"].([]any)[0].(map[string]any)["keywords"].(map[string]any)["$answered"] != true {
		t.Fatalf("copy overrides modified the original: %v", sourceRead)
	}
	args["ifInState"] = flow[0].Args["newState"]
	args["destroyFromIfInState"] = initial[0].Args["state"]
	args["create"] = object{"copy": object{"id": source, "mailboxIds": object{destination: true}}}
	retry := emailActionCalls(t, g, cfg.Token, [3]any{"Email/copy", args, "remove"})
	if len(retry) != 2 || retry[1].Name != "Email/set" || retry[1].Args["accountId"] != cfg.AccountID ||
		retry[1].Args["destroyed"].([]any)[0] != source {
		t.Fatalf("implicit source deletion: %v", retry)
	}
}

func TestAccountConfigurationFailures(t *testing.T) {
	cfg := testConfig(t)
	cfg.AdditionalAccounts = make([]AccountConfig, maxAdditionalAccounts+1)
	if _, err := New(cfg); err == nil {
		t.Fatal("accepted too many accounts")
	}
	cfg.AdditionalAccounts = []AccountConfig{{AccountID: cfg.AccountID}}
	if _, err := New(cfg); err == nil {
		t.Fatal("accepted duplicate account ID")
	}
	cfg.AdditionalAccounts = []AccountConfig{{AccountID: "other", StateDir: cfg.StateDir, IdentityEmail: cfg.IdentityEmail,
		IMAP: cfg.IMAP, SMTP: cfg.SMTP}}
	if _, err := New(cfg); err == nil {
		t.Fatal("accounts shared a state directory")
	}
	cfg.AdditionalAccounts = nil
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
}

func TestAccountStatesCancellationAndEncodingLimit(t *testing.T) {
	cfg, _ := twoAccountConfig(t, false)
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if states := g.accountStates(ctx, []string{"EmailSubmission"}); states["other"] != nil {
		t.Fatalf("cancelled observer visited secondary account: %v", states)
	}
	states := make(map[string]map[string]string)
	for i := range maxAdditionalAccounts + 1 {
		account := strings.Repeat(string(rune('a'+i)), 255)
		states[account] = map[string]string{}
		for _, kind := range append(g.eventKinds(), "VacationResponse") {
			states[account][kind] = strings.Repeat("s", 43)
		}
	}
	data, delivered := changedAccountStates(cfg.AccountID, states, nil, nil)
	wire, err := json.Marshal(object{"@type": "StateChange", "changed": data})
	if err != nil || len(wire)+103 > pushRecordSize || len(delivered) != (maxAdditionalAccounts+1)*6 {
		t.Fatalf("largest multi-account event does not fit in an encrypted push: %d", len(wire))
	}
}

func TestAccountPushIncludesAuthorizedAccounts(t *testing.T) {
	cfg, _ := twoAccountConfig(t, false)
	server, deliveries := testPushReceiver(t, &cfg)
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	g.push.stop()
	result := pushTestAPI(t, g, cfg, "set", object{"create": object{"device": object{
		"deviceClientId": "multi-account", "url": server.URL, "types": []string{"Identity"},
	}}})
	id := testPushAssignment(t, result, "created", "device")["id"].(string)
	proof := openTestPush(t, receivePush(t, deliveries).Body, nil, nil)
	if verified := pushTestAPI(t, g, cfg, "set", object{"update": object{id: object{"verificationCode": proof["verificationCode"]}}}); verified["updated"] == nil {
		t.Fatalf("verification failed: %v", verified)
	}
	g.pollPush(context.Background())
	message := openTestPush(t, receivePush(t, deliveries).Body, nil, nil)
	changed := message["changed"].(map[string]any)
	if len(changed) != 2 || changed[cfg.AccountID].(map[string]any)["Identity"] == nil ||
		changed["other"].(map[string]any)["Identity"] == nil {
		t.Fatalf("push did not include both authorized accounts: %v", message)
	}
	g.pollPush(context.Background())
	if len(deliveries) != 0 {
		t.Fatal("repeated an acknowledged state")
	}
}

func TestCopyValidationAndFailures(t *testing.T) {
	cfg, user := twoAccountConfig(t, false)
	const child = "other"
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	calls := func(name string, args object) object {
		t.Helper()
		args["accountId"] = child
		return gatewayCalls(t, g, cfg.Token, [3]any{name, args, "copy"})[0].Args
	}
	oversized := make(object)
	for i := range maxSet + 1 {
		oversized[string(rune('a'+i))] = object{}
	}
	for _, tc := range []struct {
		method string
		args   object
		code   string
	}{
		{"Blob/copy", object{"fromAccountId": cfg.AccountID}, "invalidArguments"},
		{"Blob/copy", object{"fromAccountId": child, "blobIds": []string{}}, "invalidArguments"},
		{"Blob/copy", object{"fromAccountId": cfg.AccountID, "blobIds": make([]string, maxSet+1)}, "requestTooLarge"},
		{"Blob/copy", object{"fromAccountId": "unconfigured", "blobIds": []string{}}, "fromAccountNotFound"},
		{"Email/copy", object{"fromAccountId": cfg.AccountID}, "invalidArguments"},
		{"Email/copy", object{"fromAccountId": child, "create": object{}}, "invalidArguments"},
		{"Email/copy", object{"fromAccountId": cfg.AccountID, "create": oversized}, "requestTooLarge"},
		{"Email/copy", object{"fromAccountId": cfg.AccountID, "create": object{"#bad": object{}}}, "invalidArguments"},
		{"Email/copy", object{"fromAccountId": "unconfigured", "create": object{}}, "fromAccountNotFound"},
		{"Email/copy", object{"fromAccountId": cfg.AccountID, "create": object{}, "ifFromInState": "stale"}, "stateMismatch"},
		{"Email/copy", object{"fromAccountId": cfg.AccountID, "create": object{}, "ifInState": "stale"}, "stateMismatch"},
	} {
		if got := calls(tc.method, tc.args); got["type"] != tc.code {
			t.Fatalf("%s returned %v, want %s", tc.method, got, tc.code)
		}
	}
	blob, err := g.uploads.put([]byte("source raw bytes"))
	if err != nil {
		t.Fatal(err)
	}
	childGateway := g.account(child)
	quota := childGateway.uploads.quota
	childGateway.uploads.quota = 0
	blobCopy := object{"fromAccountId": cfg.AccountID, "blobIds": []string{blob}}
	if result := calls("Blob/copy", blobCopy); result["notCopied"].(map[string]any)[blob].(map[string]any)["type"] != "overQuota" {
		t.Fatalf("blob quota not enforced: %v", result)
	}
	childGateway.uploads.quota = quota
	childGateway.uploads.files.rename = func(string, string) error { return diskError }
	if result := calls("Blob/copy", blobCopy); result["notCopied"].(map[string]any)[blob].(map[string]any)["type"] != "serverFail" {
		t.Fatalf("blob storage failure: %v", result)
	}
	added, err := user.Append("INBOX", strings.NewReader("Subject: Fixture\r\n\r\nSource\r\n"), &imap.AppendOptions{Time: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	id := emailID(mailboxID(cfg.AccountID, "INBOX"), added.UIDValidity, added.UID)
	folder := mailboxID(child, "INBOX")
	row := func(mailbox, flags, received any) object {
		return object{"id": id, "mailboxIds": mailbox, "keywords": flags, "receivedAt": received}
	}
	validAt := "2026-11-24T10:12:00Z"
	destination := object{folder: true}
	create := object{
		"shape":     object{},
		"omitted":   object{"id": id},
		"many":      row(object{folder: true, "other": true}, object{}, validAt),
		"flagshape": row(destination, "wrong", validAt),
		"flagvalue": row(destination, object{"$seen": false}, validAt),
		"dateshape": row(destination, object{}, 42),
		"datevalue": row(destination, object{}, "bad date"),
	}
	result := calls("Email/copy", object{"fromAccountId": cfg.AccountID, "create": create, "onSuccessDestroyOriginal": true})
	for key, failure := range result["notCreated"].(map[string]any) {
		if got := failure.(map[string]any)["type"]; key == "many" && got != "tooManyMailboxes" || key != "many" && got != "invalidProperties" {
			t.Fatalf("invalid item %s returned %s", key, got)
		}
	}
	if result["created"] != nil || len(result["notCreated"].(map[string]any)) != len(create) {
		t.Fatalf("invalid results: %v", result)
	}
	op := &operation{g: g, ctx: context.Background()}
	defer op.closeConnections()
	target := op.forAccount(child)
	args := rawArgs(t, object{"accountId": child, "fromAccountId": cfg.AccountID, "create": object{}})
	op.snapshotFailure = "serverUnavailable"
	if _, failure := target.copyEmails(args); failure != "serverUnavailable" {
		t.Fatal("copy ignored source outage")
	}
	op.snapshotFailure = ""
	target.snapshotFailure = "serverUnavailable"
	if _, failure := target.copyEmails(args); failure != "serverUnavailable" {
		t.Fatal("copy ignored target outage")
	}
	target.snapshotFailure = ""
	if failure := target.loadMail(); failure != "" {
		t.Fatal(failure)
	}
	data, err := json.Marshal(object{"id": id, "mailboxIds": destination})
	if err != nil {
		t.Fatal(err)
	}
	assertCode := func(want string) {
		t.Helper()
		if _, _, failure := target.copyEmail(op, data); failure["type"] != want {
			t.Fatalf("copy returned %v, want %s", failure, want)
		}
	}
	previousSize := op.snapshot.emails[id].Size
	op.snapshot.emails[id].Size = maxRaw + 1
	assertCode("tooLarge")
	op.snapshot.emails[id].Size = previousSize
	op.rawBytes = 12 * maxRaw
	assertCode("requestTooLarge")
	op.rawBytes = 0
	target.snapshot.mailbox(folder).Writable = false
	assertCode("forbidden")
	for i := range maxMessages {
		target.snapshot.emails[string(rune(i))] = nil
	}
	assertCode("overQuota")
}
