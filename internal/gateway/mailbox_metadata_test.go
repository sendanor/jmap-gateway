package gateway

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"testing"
)

type mailboxMetadataFixture struct {
	mutex sync.Mutex
	value map[string]string
	key   string
	caps  string
	fault string
}

func serveMailboxMetadataFixture(t *testing.T, cfg *Config) *mailboxMetadataFixture {
	t.Helper()
	fixture := &mailboxMetadataFixture{
		value: map[string]string{"INBOX": "", "Work": "", "Work/Child": ""},
		caps:  "IMAP4rev1 UIDPLUS",
	}
	cert, ca := testTLS(t)
	listener := tls.NewListener(listenTCP(t), cert)
	cfg.IMAP.Address, cfg.IMAP.CAFile = listener.Addr().String(), ca
	stopped := make(chan struct{})
	t.Cleanup(func() {
		_ = listener.Close()
		<-stopped
	})
	go func() {
		defer close(stopped)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			fixture.mutex.Lock()
			caps := fixture.caps
			fixture.mutex.Unlock()
			_, _ = fmt.Fprintf(conn, "* OK [CAPABILITY %s] Test IMAP\r\n", caps)
			reader := bufio.NewReader(conn)
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					break
				}
				tag, rest, _ := strings.Cut(strings.TrimSpace(line), " ")
				command, args, _ := strings.Cut(rest, " ")
				fixture.mutex.Lock()
				response := fixture.reply(t, tag, command, args, caps)
				fixture.mutex.Unlock()
				if _, err := io.WriteString(conn, response); err != nil {
					break
				}
			}
			_ = conn.Close()
		}
	}()
	return fixture
}

func (f *mailboxMetadataFixture) reply(t *testing.T, tag, command, args, caps string) string {
	t.Helper()
	if command == f.fault {
		return tag + " NO fixture rejection\r\n"
	}
	payload, status := "", "OK"
	switch command {
	case "CAPABILITY":
		payload = "* CAPABILITY " + caps + "\r\n"
	case "LOGIN":
		status = "OK [CAPABILITY " + caps + "]"
	case "LIST":
		for name := range f.value {
			payload += fmt.Sprintf("* LIST () \"/\" %q\r\n", name)
		}
	case "SELECT":
		payload = "* 0 EXISTS\r\n* OK [UIDVALIDITY 12] valid\r\n* OK [UIDNEXT 1] next\r\n"
	case "STATUS":
		name, _, _ := strings.Cut(args, " ")
		validity := 12
		if f.fault == "missing validity" {
			validity = 0
		}
		payload = fmt.Sprintf("* STATUS %s (UIDVALIDITY %d)\r\n", name, validity)
	case "GETMETADATA", "SETMETADATA":
		encoded, rest, _ := strings.Cut(args, " ")
		name, err := strconv.Unquote(encoded)
		if err != nil {
			name = encoded
		}
		if _, exists := f.value[name]; !exists || name == "INBOX" {
			t.Errorf("unexpected metadata command for mailbox %q", name)
			status = "NO"
			break
		}
		if command == "GETMETADATA" && f.value[name] != "" {
			payload = fmt.Sprintf("* METADATA %q (%q %q)\r\n", name, strings.ToUpper(f.key), f.value[name])
		}
		if command == "SETMETADATA" {
			_, value, _ := strings.Cut(rest, " ")
			marker, err := strconv.Unquote(strings.TrimSuffix(value, ")"))
			if err != nil {
				t.Errorf("invalid SETMETADATA value")
				status = "BAD"
			}
			f.value[name] = marker
		}
	default:
		t.Errorf("unexpected IMAP command %s", command)
		status = "BAD"
	}
	return payload + tag + " " + status + " fixture\r\n"
}

func TestMailboxMetadataTracksExternalRenameAndPathReuse(t *testing.T) {
	cfg := testConfig(t)
	cfg.MailboxMetadataVendor = "vendor.example"
	backend := serveMailboxMetadataFixture(t, &cfg)
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	backend.mutex.Lock()
	backend.key = g.mailboxMetadataKey()
	backend.mutex.Unlock()
	account := cfg.AccountID
	call := func() (string, object) {
		t.Helper()
		result := gatewayCalls(t, g, cfg.Token, [3]any{"Mailbox/get", object{"accountId": account}, "metadata"})[0]
		return result.Name, result.Args
	}
	checkFailure := func() {
		t.Helper()
		name, result := call()
		if name != "error" || result["type"] != "serverFail" {
			t.Fatalf("expected a sync error, got %s %v", name, result)
		}
	}
	checkFailure()
	backend.mutex.Lock()
	backend.caps += " METADATA"
	backend.mutex.Unlock()
	root := "m-existing"
	child := mailboxID(account, "Work/Child")
	if failure := g.saveMailboxState(mailboxState{Details: map[string]mailboxDetails{
		"Work": {ID: root, SortOrder: 7, Subscribed: true},
	}}); failure != "" {
		t.Fatal(failure)
	}
	list := func() map[string]object {
		t.Helper()
		name, result := call()
		if name != "Mailbox/get" {
			t.Fatalf("Mailbox/get returned %s %v", name, result)
		}
		records := make(map[string]object)
		for _, value := range result["list"].([]any) {
			record := value.(map[string]any)
			records[record["id"].(string)] = record
		}
		return records
	}
	if records := list(); records[root]["name"] != "Work" || records[child]["parentId"] != root {
		t.Fatal("initial metadata attachment changed existing mailbox IDs")
	}
	backend.mutex.Lock()
	backend.value["Archive"], backend.value["Archive/Child"] = backend.value["Work"], backend.value["Work/Child"]
	backend.value["Work"], backend.value["Work/Child"] = "", ""
	backend.mutex.Unlock()
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	g, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	records := list()
	if records[root]["name"] != "Archive" || records[root]["sortOrder"] != float64(7) ||
		records[root]["isSubscribed"] != true || records[child]["parentId"] != root || len(records) != 5 {
		t.Fatalf("external rename or path reuse lost identity or settings: %v", records)
	}
	state, failure := g.loadMailboxState()
	if failure != "" || state.MetadataIDs["Work"] == root || state.MetadataIDs["Work/Child"] == child ||
		state.MetadataIDs["Archive"] != root || state.MetadataIDs["Archive/Child"] != child {
		t.Fatalf("unexpected persisted identities: %v, %s", state.MetadataIDs, failure)
	}
	for _, marker := range []string{
		strings.Repeat("x", 300), root + ".bad", root + "." + g.signMailboxID(root),
	} {
		backend.mutex.Lock()
		backend.value["Unknown"] = marker
		backend.mutex.Unlock()
		checkFailure()
	}
	for _, command := range []string{"STATUS", "missing validity", "GETMETADATA", "SETMETADATA"} {
		backend.mutex.Lock()
		backend.value["Unknown"] = ""
		backend.fault = command
		backend.mutex.Unlock()
		checkFailure()
	}
	backend.mutex.Lock()
	backend.fault = ""
	backend.mutex.Unlock()
	replace := g.ledger.files.rename
	g.ledger.files.rename = func(string, string) error { return diskError }
	checkFailure()
	g.ledger.files.rename = replace
	if len(list()) != 6 {
		t.Fatal("retry did not recover a confirmed annotation after local state write failure")
	}
	recovered, failure := g.loadMailboxState()
	if failure != "" || len(recovered.MetadataIDs) != 5 {
		t.Fatalf("recovered metadata state: %v, %s", recovered.MetadataIDs, failure)
	}
	for path, id := range state.MetadataIDs {
		if recovered.MetadataIDs[path] != id {
			t.Fatalf("retry changed the ID of %q", path)
		}
	}
	list()
	g.config.MailboxMetadataVendor = "vendor.other"
	checkFailure()
}
