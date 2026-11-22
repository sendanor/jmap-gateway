package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
)

func TestEmailChangesStableAcrossRestartAndExternalMutations(t *testing.T) {
	config := testConfig(t)
	cert, ca := testTLS(t)
	config.IMAP.CAFile = ca
	address, user := serveTestIMAP(t, config.IMAP, cert, imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapUIDPlus: {}}, nil)
	config.IMAP.Address = address
	appendExternal := func(path, subject string) string {
		t.Helper()
		data, err := user.Append(path, strings.NewReader("Subject: "+subject+"\r\n\r\nMessage\r\n"), &imap.AppendOptions{Time: time.Now()})
		if err != nil {
			t.Fatal(err)
		}
		return emailID(mailboxID(config.AccountID, path), data.UIDValidity, data.UID)
	}
	updated := appendExternal("INBOX", "Seen")
	destroyed := appendExternal("Drafts", "Removed")
	g, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	account := config.AccountID
	get := func(kind string) string {
		t.Helper()
		result := gatewayCalls(t, g, config.Token, [3]any{kind + "/get", object{"accountId": account, "properties": []string{"id"}}, "get"})[0]
		if result.Name != kind+"/get" {
			t.Fatalf("read state: %v", result)
		}
		return result.Args["state"].(string)
	}
	changes := func(kind, state string, limit int) object {
		t.Helper()
		result := gatewayCalls(t, g, config.Token, [3]any{
			kind + "/changes", object{"accountId": account, "sinceState": state, "maxChanges": limit}, "changes",
		})[0]
		if result.Name != kind+"/changes" || result.Args["oldState"] != state {
			t.Fatalf("read changes: %v", result)
		}
		return result.Args
	}
	first, mailboxState := get("Email"), get("Mailbox")
	created := appendExternal("INBOX", "New")
	if err := user.Delete("Drafts"); err != nil {
		t.Fatal(err)
	}
	update := gatewayCalls(t, g, config.Token, [3]any{
		"Email/set", object{"accountId": account, "update": object{updated: object{"keywords/$seen": true}}}, "seen",
	})[0]
	if update.Args["updated"] == nil {
		t.Fatalf("update seen state: %v", update)
	}
	through := get("Email")
	page := changes("Email", first, 1)
	pageState, hasMore := page["newState"].(string), page["hasMoreChanges"]
	if !strings.HasPrefix(pageState, "page.") || hasMore != true {
		t.Fatalf("invalid intermediate state: %v", page)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	g, err = New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	later := appendExternal("INBOX", "Added between pages")
	latest := get("Email")
	if latest == through {
		t.Fatal("external delivery did not change Email state")
	}
	got := map[string]string{}
	for {
		total := 0
		for _, key := range []string{"created", "updated", "destroyed"} {
			for _, value := range page[key].([]any) {
				id := value.(string)
				if got[id] != "" {
					t.Fatalf("Email %s returned twice", id)
				}
				got[id] = key
				total++
			}
		}
		if total != 1 {
			t.Fatalf("page used a limit of one but returned %d records", total)
		}
		if page["newState"] == through {
			if page["hasMoreChanges"] != true {
				t.Fatal("new delivery after page one was missed")
			}
			break
		}
		page = changes("Email", page["newState"].(string), 1)
	}
	if !reflect.DeepEqual(got, map[string]string{created: "created", updated: "updated", destroyed: "destroyed"}) {
		t.Fatalf("incorrect coalesced page window: %v", got)
	}
	final := changes("Email", through, 1)
	if !reflect.DeepEqual(final["created"], []any{later}) || final["newState"] != latest || final["hasMoreChanges"] != false {
		t.Fatalf("incorrect catch-up after paginated state: %v", final)
	}
	mailboxes := changes("Mailbox", mailboxState, 10)
	changedMailboxes := []string{mailboxID(account, "INBOX"), mailboxID(account, "Drafts/Child")}
	slices.Sort(changedMailboxes)
	if mailboxes["updatedProperties"] != nil ||
		!reflect.DeepEqual(mailboxes["destroyed"], []any{mailboxID(account, "Drafts")}) ||
		!reflect.DeepEqual(mailboxes["updated"], []any{changedMailboxes[0], changedMailboxes[1]}) {
		t.Fatalf("unexpected external mailbox changes: %v", mailboxes)
	}
}

func TestMailboxChangesCountProjectionAndCreatedMailbox(t *testing.T) {
	config := testConfig(t)
	cert, ca := testTLS(t)
	config.IMAP.CAFile = ca
	address, user := serveTestIMAP(t, config.IMAP, cert, imap.CapSet{imap.CapIMAP4rev1: {}}, nil)
	config.IMAP.Address = address
	g, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	account := config.AccountID
	before := gatewayCalls(t, g, config.Token, [3]any{
		"Mailbox/get", object{"accountId": account, "properties": []string{"id"}}, "state",
	})[0].Args["state"]
	if _, err := user.Append("INBOX", strings.NewReader("Subject: New message\r\n\r\nBody"), &imap.AppendOptions{Time: time.Now()}); err != nil {
		t.Fatal(err)
	}
	calls := gatewayCalls(t, g, config.Token,
		[3]any{"Mailbox/changes", object{"accountId": account, "sinceState": before}, "changes"},
		[3]any{"Mailbox/get", object{
			"accountId":   account,
			"#ids":        object{"resultOf": "changes", "name": "Mailbox/changes", "path": "/updated"},
			"#properties": object{"resultOf": "changes", "name": "Mailbox/changes", "path": "/updatedProperties"},
		}, "counts"},
	)
	counts := calls[1].Args["list"].([]any)[0].(map[string]any)
	for _, property := range []string{"totalEmails", "totalThreads", "unreadEmails", "unreadThreads"} {
		if counts[property] != float64(1) {
			t.Fatalf("%q missing from count projection: %v", property, counts)
		}
	}
	if len(counts) != 5 {
		t.Fatalf("count projection returned unrelated properties: %v", counts)
	}
	if err := user.Create("External", nil); err != nil {
		t.Fatal(err)
	}
	change := gatewayCalls(t, g, config.Token, [3]any{
		"Mailbox/changes", object{"accountId": account, "sinceState": calls[0].Args["newState"]}, "changes",
	})[0]
	if change.Args["updatedProperties"] != nil || !reflect.DeepEqual(change.Args["created"], []any{mailboxID(account, "External")}) {
		t.Fatalf("unexpected mailbox creation: %v", change)
	}
}

func TestChangesInvalidStatesLimitsAndRevertedUpdates(t *testing.T) {
	config := testConfig(t)
	g, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	op := operation{g: g, snapshot: &snapshot{emails: map[string]*emailMeta{}}}
	id := emailID("mailbox", 1, 1)
	op.snapshot.emails[id] = &emailMeta{ID: id, Keywords: map[string]bool{}}
	first := op.state("Email")
	op.snapshot.emails[id].Keywords["$seen"] = true
	op.state("Email")
	delete(op.snapshot.emails[id].Keywords, "$seen")
	transient := emailID("mailbox", 1, 2)
	op.snapshot.emails[transient] = &emailMeta{ID: transient}
	op.state("Email")
	delete(op.snapshot.emails, transient)
	final := op.state("Email")
	response, failure := op.changes("Email", rawArgs(t, object{"sinceState": first}))
	if failure != "" || first == final || response["newState"] != final ||
		!slices.Equal(response["updated"].([]string), []string{id}) ||
		len(response["created"].([]string))+len(response["destroyed"].([]string)) != 0 {
		t.Fatalf("unexpected reverted/expired-record response: %v, %s", response, failure)
	}

	for _, test := range []struct {
		args object
		want string
	}{
		{object{}, "invalidArguments"},
		{object{"sinceState": 1}, "invalidArguments"},
		{object{"sinceState": final, "maxChanges": 0}, "invalidArguments"},
		{object{"sinceState": final, "maxChanges": int64(1 << 53)}, "invalidArguments"},
		{object{"sinceState": "expired"}, "cannotCalculateChanges"},
		{object{"sinceState": "page.invalid"}, "cannotCalculateChanges"},
		{object{"sinceState": g.encodeCursor(changeCursor{Kind: "Mailbox", From: first, Through: final, After: id})}, "cannotCalculateChanges"},
		{object{"sinceState": g.encodeCursor(changeCursor{Kind: "Email", From: final, Through: first, After: id})}, "cannotCalculateChanges"},
	} {
		if _, failure := op.changes("Email", rawArgs(t, test.args)); failure != test.want {
			t.Fatalf("changes with %v returned %q, expected %q", test.args, failure, test.want)
		}
	}
	op.snapshot, op.snapshotFailure = nil, "serverUnavailable"
	if _, failure := op.changes("Email", rawArgs(t, object{"sinceState": final})); failure != "serverUnavailable" {
		t.Fatalf("upstream unavailable returned %q", failure)
	}
}

func TestIdentityChangesPersistsAcrossConfigurationReload(t *testing.T) {
	config := testConfig(t)
	g, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	before := gatewayCalls(t, g, config.Token, [3]any{"Identity/get", object{"accountId": config.AccountID}, "identity"})[0].Args["state"]
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	config.IdentityName = "Renamed identity"
	g, err = New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	result := gatewayCalls(t, g, config.Token, [3]any{
		"Identity/changes", object{"accountId": config.AccountID, "sinceState": before}, "changes",
	})[0]
	if result.Name != "Identity/changes" || result.Args["newState"] == before ||
		!reflect.DeepEqual(result.Args["updated"], []any{identityID}) {
		t.Fatalf("unexpected identity changes after config reload: %v", result)
	}
}

func TestChangeHistoryRetentionAndFailedWrite(t *testing.T) {
	h := changeHistory{dir: t.TempDir(), files: localAtomicFiles, tracks: make(map[string]*changeTrack)}
	path := filepath.Join(h.dir, "changes-Email.json")
	if err := os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	diskFailure := true
	h.files.rename = func(old, new string) error {
		if diskFailure {
			return diskError
		}
		return localAtomicFiles.rename(old, new)
	}
	stamps := func() map[string]recordStamp { return map[string]recordStamp{"email": {Hash: "original"}} }
	track := h.observe("Email", "initial", stamps)
	if !track.dirty {
		t.Fatal("history did not remember a failed write")
	}
	diskFailure = false
	h.observe("Email", "initial", stamps)
	stored, err := os.ReadFile(path)
	if err != nil || !json.Valid(stored) || track.dirty {
		t.Fatalf("unchanged state did not retry failed persistence: %v", err)
	}
	track.Past = make([]reverseStep, maxHistorySteps+1)
	track.Past[0].State = "evicted"
	track.trim()
	if len(track.Past) != maxHistorySteps {
		t.Fatal("state-step retention was not bounded")
	}
	if _, _, found := track.at("evicted"); found {
		t.Fatal("discarded state was still available")
	}
	big := make(map[string]recordStamp, maxHistoryRecords)
	for i := range maxHistoryRecords {
		big[fmt.Sprint(i)] = recordStamp{}
	}
	track.Past = []reverseStep{{State: "evicted", Previous: big}, {State: "retained", Previous: map[string]recordStamp{"one": {}}}}
	track.trim()
	if len(track.Past) != 1 || track.Past[0].State != "retained" {
		t.Fatal("change-record retention was not bounded")
	}
}

func TestSyncCursorKeyFailuresAndIsolation(t *testing.T) {
	config := testConfig(t)
	keyPath := filepath.Join(config.StateDir, "changes.key")
	if err := os.WriteFile(keyPath, []byte("short"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(config); err == nil || err.Error() != "cannot read synchronization key" {
		t.Fatalf("invalid cursor key produced %v", err)
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	broken := localAtomicFiles
	broken.rename = func(string, string) error { return diskError }
	if _, err := openChangeHistory(config.StateDir, broken); err == nil || err.Error() != "cannot create synchronization key" {
		t.Fatalf("failed key write produced %v", err)
	}
	gateway, err := New(config)
	if err != nil {
		t.Fatalf("failed startup did not release the account lock: %v", err)
	}
	defer gateway.Close()
	other := testConfig(t)
	alternate, err := New(other)
	if err != nil {
		t.Fatal(err)
	}
	defer alternate.Close()
	cursor := changeCursor{Kind: "Email", From: "initial", Through: "later", After: "known"}
	token := gateway.encodeCursor(cursor)
	if _, ok := alternate.decodeCursor(token, "Email"); ok {
		t.Fatal("distinct account installations accepted the same cursor")
	}
	if decoded, ok := gateway.decodeCursor(token, "Email"); !ok || decoded != cursor {
		t.Fatal("cursor did not survive a valid encode/decode")
	}
}
