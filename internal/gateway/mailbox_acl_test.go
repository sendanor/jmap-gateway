package gateway

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
)

func serveMailboxACLFixture(t *testing.T, cfg *Config, phase *atomic.Int32) {
	t.Helper()
	cert, ca := testTLS(t)
	listener := tls.NewListener(listenTCP(t), cert)
	stopped := make(chan struct{})
	t.Cleanup(func() {
		_ = listener.Close()
		<-stopped
	})
	cfg.IMAP.Address, cfg.IMAP.CAFile = listener.Addr().String(), ca
	go func() {
		defer close(stopped)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			reader := bufio.NewReader(conn)
			_, _ = io.WriteString(conn, "* OK [CAPABILITY IMAP4rev1 ACL UIDPLUS MOVE] Fixture\r\n")
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					break
				}
				tag, rest, _ := strings.Cut(strings.TrimSpace(line), " ")
				command, args, _ := strings.Cut(rest, " ")
				name := strings.Trim(args, "\"")
				var payload string
				status := "OK"
				switch command {
				case "CAPABILITY":
					payload = "* CAPABILITY IMAP4rev1 ACL UIDPLUS MOVE\r\n"
				case "LOGIN":
					status = "OK [CAPABILITY IMAP4rev1 ACL UIDPLUS MOVE]"
				case "LIST":
					payload = "* LIST () \"/\" INBOX\r\n* LIST () \"/\" Shared\r\n* LIST () \"/\" Destination\r\n"
				case "MYRIGHTS":
					rights := "lrskiptwxea"
					switch name {
					case "Destination":
						if phase.Load() >= 5 {
							rights = "lri"
						}
					case "INBOX":
						name = "inbox"
						rights = "lrs"
						if phase.Load() == 1 {
							rights = "lrw"
						}
						if phase.Load() >= 4 {
							rights = "lrstew"
						}
					case "Shared":
						rights = "lk"
						if phase.Load() == 2 {
							status = "NO"
						}
						if phase.Load() == 3 {
							name = "Mismatch"
						}
					}
					payload = fmt.Sprintf("* MYRIGHTS %s %s\r\n", name, rights)
				case "SELECT":
					if name == "Shared" {
						t.Error("MYRIGHTS listed no read permission but gateway issued SELECT")
						status = "NO"
					}
					count := 0
					if name == "INBOX" {
						count = 1
						if phase.Load() == 4 {
							status = "OK [READ-ONLY]"
						}
					}
					payload = fmt.Sprintf("* %d EXISTS\r\n* OK [UIDVALIDITY 12] valid\r\n* OK [UIDNEXT 2] next\r\n", count)
				case "FETCH":
					header := "Subject: ACL fixture\r\n\r\n"
					flags := ""
					if phase.Load() == 6 {
						flags = `\Seen`
					}
					payload = fmt.Sprintf("* 1 FETCH (UID 1 FLAGS (%s) INTERNALDATE \"22-Nov-2026 17:00:00 +0000\" RFC822.SIZE 64 BODY[HEADER.FIELDS (MESSAGE-ID IN-REPLY-TO REFERENCES SUBJECT)]<0> {%d}\r\n%s)\r\n",
						flags, len(header), header)
				default:
					t.Errorf("unexpected IMAP command %q", command)
					status = "BAD"
				}
				if _, err := fmt.Fprintf(conn, "%s%s %s Fixture\r\n", payload, tag, status); err != nil {
					break
				}
			}
			_ = conn.Close()
		}
	}()
}

func TestMailboxACLDiscoveryAndChanges(t *testing.T) {
	cfg := testConfig(t)
	var phase atomic.Int32
	serveMailboxACLFixture(t, &cfg, &phase)
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	call := func(method string, args object) [3]any {
		args["accountId"] = cfg.AccountID
		return [3]any{method, args, method}
	}
	inbox, shared, dest := mailboxID(cfg.AccountID, "INBOX"), mailboxID(cfg.AccountID, "Shared"), mailboxID(cfg.AccountID, "Destination")
	first := gatewayCalls(t, g, cfg.Token,
		call("Mailbox/get", object{"ids": []string{inbox, shared, dest}}),
		call("Email/query", object{}),
		call("Email/query", object{"filter": object{"inMailbox": shared}}),
		call("Email/query", object{"filter": object{"inMailboxOtherThan": []string{shared}}}))
	if first[0].Name != "Mailbox/get" || first[1].Name != "Email/query" {
		t.Fatalf("ACL fixture scan failed: %v", first)
	}
	mailboxes := first[0].Args["list"].([]any)
	rights := func(entry any) map[string]any { return entry.(map[string]any)["myRights"].(map[string]any) }
	for i, yes := range [][]string{{"mayReadItems", "maySetSeen"}, {"mayCreateChild"},
		{"mayReadItems", "maySetSeen", "maySetKeywords", "mayAddItems", "mayRemoveItems", "mayCreateChild", "mayRename", "mayDelete", "maySubmit"}} {
		actual := rights(mailboxes[i])
		for name, value := range actual {
			if value != contains(yes, name) {
				t.Fatalf("mailbox %d unexpected %s: %v", i, name, actual)
			}
		}
	}
	if first[2].Args["type"] != "forbidden" || first[3].Args["type"] != "forbidden" {
		t.Fatalf("lookup-only mailbox appeared in message search: %v", first)
	}
	id := first[1].Args["ids"].([]any)[0].(string)
	denied := gatewayCalls(t, g, cfg.Token,
		call("SearchSnippet/get", object{"emailIds": []string{id}, "filter": object{"inMailbox": shared}}),
		call("Email/set", object{"update": object{id: object{"keywords/$flagged": true}}}),
		call("Email/set", object{"update": object{id: object{"mailboxIds": object{dest: true}}}}),
		call("Email/set", object{"destroy": []string{id}}))
	if denied[0].Args["type"] != "forbidden" || denied[1].Args["notUpdated"].(map[string]any)[id].(map[string]any)["type"] != "forbidden" ||
		denied[2].Args["notUpdated"].(map[string]any)[id].(map[string]any)["type"] != "forbidden" ||
		denied[3].Args["notDestroyed"].(map[string]any)[id].(map[string]any)["type"] != "forbidden" {
		t.Fatalf("forbidden operation reached IMAP: %v", denied)
	}
	phase.Store(1)
	deltas := gatewayCalls(t, g, cfg.Token,
		call("Mailbox/changes", object{"sinceState": first[0].Args["state"]}),
		call("Mailbox/get", object{"ids": []string{inbox}}))
	actual := rights(deltas[1].Args["list"].([]any)[0])
	if !reflect.DeepEqual(deltas[0].Args["updated"], []any{inbox}) || deltas[0].Args["updatedProperties"] != nil ||
		actual["maySetSeen"] != false || actual["maySetKeywords"] != true {
		t.Fatalf("ACL-only changes not synchronized: %v", deltas)
	}
	for _, fault := range []int32{2, 3} {
		phase.Store(fault)
		result := gatewayCalls(t, g, cfg.Token, call("Mailbox/get", object{}))[0]
		if result.Name != "error" || result.Args["type"] != "serverFail" {
			t.Fatalf("unverified ACL rights advertised after fault %d: %v", fault, result)
		}
	}
	phase.Store(4)
	readOnly := gatewayCalls(t, g, cfg.Token, call("Mailbox/get", object{"ids": []string{inbox}}))[0]
	if actual := rights(readOnly.Args["list"].([]any)[0]); actual["mayReadItems"] != true || actual["maySetSeen"] != false ||
		actual["maySetKeywords"] != false || actual["mayRemoveItems"] != false {
		t.Fatalf("incorrect forced read-only rights: %v", actual)
	}
	for _, currentPhase := range []int32{5, 6} {
		phase.Store(currentPhase)
		patch := object{"mailboxIds": object{dest: true}}
		if currentPhase == 5 {
			patch["keywords/$seen"] = true
		}
		move := gatewayCalls(t, g, cfg.Token, call("Email/set", object{"update": object{id: patch}}))[0]
		if move.Args["notUpdated"].(map[string]any)[id].(map[string]any)["type"] != "forbidden" {
			t.Fatalf("move would lose requested or existing flags: %v", move)
		}
	}
}

func TestMailboxACLKeywordReplacement(t *testing.T) {
	b := &box{ACL: &mailboxACL{Read: true, SetSeen: true}}
	b.Writable = true
	if _, failure := appendEmail(nil, b, nil, []imap.Flag{imap.FlagFlagged}, time.Now()); failure != "forbidden" {
		t.Fatalf("append would lose a requested flag: %s", failure)
	}
	current := map[string]bool{"$flagged": true}
	if b.allowsKeywordChange(current, keywordChange{replace: true, values: map[string]bool{"$seen": true}}) {
		t.Fatal("keyword replacement implicitly removed a flag without permission")
	}
	if !b.allowsKeywordChange(current, keywordChange{replace: true, values: map[string]bool{"$flagged": true, "$seen": true}}) {
		t.Fatal("keeping an existing flag requires no change permission")
	}
}
