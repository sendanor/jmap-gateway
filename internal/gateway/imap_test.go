package gateway

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-imap/v2/imapserver"
)

var fixtureIMAPError = &imap.Error{Type: imap.StatusResponseTypeNo, Text: "fixture rejection"}

type imapFaultSession struct {
	imapserver.Session
	fault string
}

func (s imapFaultSession) List(w *imapserver.ListWriter, ref string, patterns []string, options *imap.ListOptions) error {
	switch s.fault {
	case "list-rejected":
		return fixtureIMAPError
	case "folder-limit":
		for i := range maxMailboxes + 1 {
			if err := w.WriteList(&imap.ListData{Mailbox: fmt.Sprintf("folder-%03d", i)}); err != nil {
				return err
			}
		}
		return nil
	case "roles":
		for _, item := range []*imap.ListData{
			{Mailbox: "Drafts", Attrs: []imap.MailboxAttr{imap.MailboxAttrDrafts}},
			{Mailbox: "Drafts/Child", Delim: '/', Attrs: []imap.MailboxAttr{imap.MailboxAttrDrafts}},
			{Mailbox: "Plain", Attrs: []imap.MailboxAttr{imap.MailboxAttrArchive}},
			{Mailbox: "Root", Attrs: []imap.MailboxAttr{imap.MailboxAttrNoSelect}},
		} {
			if err := w.WriteList(item); err != nil {
				return err
			}
		}
		return nil
	default:
		return s.Session.List(w, ref, patterns, options)
	}
}

func (s imapFaultSession) Select(name string, opts *imap.SelectOptions) (*imap.SelectData, error) {
	if s.fault == "select-rejected" {
		return nil, fixtureIMAPError
	}
	data, err := s.Session.Select(name, opts)
	if err != nil {
		return nil, err
	}
	switch s.fault {
	case "message-limit":
		data.NumMessages = maxMessages + 1
	case "fetch-rejected", "missing-meta", "missing-thread-headers":
		data.NumMessages = 1
	case "read-only":
		data.ReadOnly = true
	}
	return data, nil
}

func (s imapFaultSession) Fetch(w *imapserver.FetchWriter, set imap.NumSet, options *imap.FetchOptions) error {
	rawBody := len(options.BodySection) != 0 && options.BodySection[0].Specifier == imap.PartSpecifierNone
	searchHeaders := len(options.BodySection) != 0 && options.BodySection[0].Specifier == imap.PartSpecifierHeader &&
		len(options.BodySection[0].HeaderFields) == 0
	switch {
	case s.fault == "fetch-rejected", s.fault == "flags-rejected" && len(options.BodySection) == 0:
		return fixtureIMAPError
	case s.fault == "missing-meta", s.fault == "missing-body" && rawBody:
		row := w.CreateMessage(1)
		row.WriteUID(1)
		return row.Close()
	case s.fault == "missing-thread-headers":
		row := w.CreateMessage(1)
		row.WriteUID(1)
		row.WriteInternalDate(time.Now())
		row.WriteRFC822Size(32)
		return row.Close()
	case searchHeaders && (s.fault == "missing-search-headers" || s.fault == "invalid-search-headers"):
		row := w.CreateMessage(1)
		row.WriteUID(1)
		if s.fault == "invalid-search-headers" {
			const bad = "broken header\r\n\r\n"
			body := row.WriteBodySection(options.BodySection[0], int64(len(bad)))
			_, _ = io.WriteString(body, bad)
			_ = body.Close()
		}
		return row.Close()
	case s.fault == "unchanged-flags":
		row := w.CreateMessage(1)
		row.WriteUID(1)
		row.WriteFlags(nil)
		return row.Close()
	case s.fault == "body-rejected" && rawBody:
		return fixtureIMAPError
	case s.fault == "no-message", s.fault == "body-gone" && rawBody:
		return nil
	default:
		return s.Session.Fetch(w, set, options)
	}
}

func (s imapFaultSession) Store(w *imapserver.FetchWriter, set imap.NumSet, flags *imap.StoreFlags, opts *imap.StoreOptions) error {
	switch s.fault {
	case "store-rejected":
		return fixtureIMAPError
	case "flags-rejected", "unchanged-flags", "no-message":
		return nil
	default:
		return s.Session.Store(w, set, flags, opts)
	}
}

func (s imapFaultSession) Append(name string, body imap.LiteralReader, opts *imap.AppendOptions) (*imap.AppendData, error) {
	switch s.fault {
	case "append-rejected", "missing-appenduid":
		if _, err := io.Copy(io.Discard, body); err != nil {
			return nil, err
		}
		if s.fault == "append-rejected" {
			return nil, fixtureIMAPError
		}
		return nil, nil
	default:
		return s.Session.Append(name, body, opts)
	}
}

func testGatewayForIMAP(t *testing.T, tlsCert *tls.Config, ca, fault string, caps imap.CapSet) *Gateway {
	t.Helper()
	c := testConfig(t)
	c.IMAP.CAFile = ca
	c.IMAP.Address, _ = serveTestIMAP(t, c.IMAP, tlsCert, caps, func(session imapserver.Session) imapserver.Session {
		return imapFaultSession{Session: session, fault: fault}
	})
	g, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	return g
}

func TestIMAPScanFailuresAndRoles(t *testing.T) {
	cert, ca := testTLS(t)
	for _, fault := range []string{"list-rejected", "folder-limit", "select-rejected", "message-limit", "fetch-rejected", "missing-meta", "missing-thread-headers", "roles"} {
		t.Run(fault, func(t *testing.T) {
			g := testGatewayForIMAP(t, cert, ca, fault, imap.CapSet{imap.CapIMAP4rev1: {}})
			op := operation{g: g, ctx: context.Background()}
			defer func() {
				if op.closeIMAP != nil {
					op.closeIMAP()
				}
			}()
			failure := op.loadMail()
			if fault != "roles" {
				if failure != "serverFail" {
					t.Fatalf("%s returned %q", fault, failure)
				}
				return
			}
			if failure != "" || len(op.snapshot.boxes) != 3 {
				t.Fatalf("role listing failed: %q", failure)
			}
			if op.snapshot.boxes[0].Role != "drafts" || op.snapshot.boxes[1].Role != "" ||
				op.snapshot.boxes[2].Role != "archive" {
				t.Fatalf("duplicate special-use mailbox or hidden container included: %+v", op.snapshot.boxes)
			}
		})
	}
}

func TestIMAPMessageReadAndWriteFailures(t *testing.T) {
	cert, ca := testTLS(t)
	for _, test := range []struct {
		name, fault, want string
		action            func(*imapclient.Client, *emailMeta, *box) string
		legacy            bool
	}{
		{"raw too large", "", "serverFail", func(c *imapclient.Client, e *emailMeta, _ *box) string {
			e.Size = maxRaw + 1
			_, failure := fetchRaw(c, e)
			return failure
		}, false},
		{"change of UID validity", "", "notFound", func(c *imapclient.Client, e *emailMeta, _ *box) string {
			e.Validity++
			_, failure := fetchRaw(c, e)
			return failure
		}, false},
		{"select failed", "select-rejected", "serverFail", func(c *imapclient.Client, e *emailMeta, _ *box) string {
			_, failure := fetchRaw(c, e)
			return failure
		}, false},
		{"fetch failed", "fetch-rejected", "serverFail", func(c *imapclient.Client, e *emailMeta, _ *box) string {
			_, failure := fetchRaw(c, e)
			return failure
		}, false},
		{"missing body literal", "missing-body", "serverFail", func(c *imapclient.Client, e *emailMeta, _ *box) string {
			_, failure := fetchRaw(c, e)
			return failure
		}, false},
		{"message lost", "no-message", "notFound", func(c *imapclient.Client, e *emailMeta, _ *box) string {
			_, failure := fetchRaw(c, e)
			return failure
		}, false},
		{"read only store", "read-only", "forbidden", testSetSeen, false},
		{"store failed", "store-rejected", "serverFail", testSetSeen, false},
		{"flags fetch failed", "flags-rejected", "serverFail", testSetSeen, false},
		{"store ignored", "unchanged-flags", "forbidden", testSetSeen, false},
		{"message lost during flags update", "no-message", "notFound", testSetSeen, false},
		{"read only append", "", "forbidden", func(c *imapclient.Client, e *emailMeta, b *box) string {
			b.Writable = false
			return testAppend(c, e, b)
		}, false},
		{"server has no APPENDUID support", "", "serverFail", testAppend, true},
		{"append rejected", "append-rejected", "serverFail", testAppend, false},
		{"append omitted APPENDUID", "missing-appenduid", "serverFail", testAppend, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			caps := imap.CapSet{imap.CapIMAP4rev1: {}}
			if !test.legacy {
				caps[imap.CapUIDPlus] = struct{}{}
			}
			g := testGatewayForIMAP(t, cert, ca, test.fault, caps)
			client, closeClient, err := g.connectIMAP(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer closeClient()
			meta := &emailMeta{Path: "Drafts", Validity: 2, UID: 1, Size: 1}
			folder := &box{Path: "Drafts", ID: "drafts", Writable: true}
			if failure := test.action(client, meta, folder); failure != test.want {
				t.Fatalf("returned %q, want %q", failure, test.want)
			}
		})
	}
}

func testSetSeen(c *imapclient.Client, e *emailMeta, _ *box) string {
	_, failure := storeEmailKeywords(c, e, keywordChange{values: map[string]bool{"$seen": true}})
	return failure
}

func testAppend(c *imapclient.Client, _ *emailMeta, b *box) string {
	_, failure := appendEmail(c, b, []byte("Subject: draft\r\n\r\nbody\r\n"), []imap.Flag{imap.FlagDraft}, time.Now())
	return failure
}

func TestIMAPTransportFailures(t *testing.T) {
	cert, ca := testTLS(t)
	for _, fault := range []string{"unavailable", "untrusted", "login"} {
		t.Run(fault, func(t *testing.T) {
			g := testGatewayForIMAP(t, cert, ca, "", imap.CapSet{imap.CapIMAP4rev1: {}})
			switch fault {
			case "unavailable":
				closed := listenTCP(t)
				g.config.IMAP.Address = closed.Addr().String()
				_ = closed.Close()
			case "untrusted":
				g.imapTLS = ServerTLS()
				g.imapTLS.ServerName = "127.0.0.1"
			case "login":
				g.config.IMAP.Password = "bad password"
			}
			op := operation{g: g, ctx: context.Background()}
			if failure := op.loadMail(); failure != "serverUnavailable" {
				t.Fatalf("returned %q", failure)
			}
		})
	}
}

func TestDigestRejectsNonSerializableState(t *testing.T) {
	defer func() {
		if recovered := recover(); recovered == nil || !strings.Contains(fmt.Sprint(recovered), "non-serializable state") {
			t.Errorf("wrong digest outcome: %v", recovered)
		}
	}()
	digest(make(chan int))
}
