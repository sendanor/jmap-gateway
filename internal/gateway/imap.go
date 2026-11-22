package gateway

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-message/charset"
)

const (
	maxMailboxes = 128
	maxMessages  = 10000
	maxRaw       = 2 << 20
)

type box struct {
	ID, Path, Name, ParentID, Role string
	Subscribed, Writable           bool
	Total, Unread                  int
	TotalThreads, UnreadThreads    int
	CanRemoveItems                 bool
	SortOrder                      uint32
	CanCreateChild, CanChangePath  bool
	ACL                            *mailboxACL
	Delimiter                      rune     `json:"-"`
	Validity                       uint32   `json:"-"`
	NextUID                        imap.UID `json:"-"`
}

type emailMeta struct {
	ID, MailboxID, Path string
	Validity            uint32
	UID                 imap.UID
	Received            time.Time
	Size                int64
	Keywords            map[string]bool
	ThreadID            string `json:",omitempty"`
}

var defaultEmailProperties = []string{
	"id", "blobId", "threadId", "mailboxIds", "keywords", "size", "receivedAt",
	"messageId", "inReplyTo", "references", "sender", "from", "to", "cc", "bcc",
	"replyTo", "subject", "sentAt", "hasAttachment", "preview", "bodyValues",
	"textBody", "htmlBody", "attachments",
}

func metaOnly(properties []string) bool {
	for _, property := range properties {
		switch property {
		case "id", "blobId", "threadId", "mailboxIds", "keywords", "receivedAt", "size":
		default:
			return false
		}
	}
	return true
}

func (e *emailMeta) fields() object {
	return object{
		"id": e.ID, "blobId": "b-" + e.ID[2:], "threadId": threadID(e.ID, e.ThreadID),
		"mailboxIds": map[string]bool{e.MailboxID: true}, "keywords": e.Keywords,
		"receivedAt": e.Received.Format(time.RFC3339), "size": e.Size,
	}
}

type snapshot struct {
	boxes         []*box
	emails        map[string]*emailMeta
	paths         map[string]bool
	rootDelimiter rune
	mailboxes     mailboxState
	moves         emailMoveState
}

func digest(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		panic("non-serializable state")
	}
	sum := sha256.Sum256(data)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (s *snapshot) state(kind string) string {
	if kind == "Mailbox" {
		return digest(s.boxes)
	}
	return digest(s.emails)
}

func mailboxID(account, path string) string {
	if strings.EqualFold(path, "INBOX") {
		path = "INBOX"
	}
	return "m-" + digest([]string{account, path})
}

func emailID(mailbox string, validity uint32, uid imap.UID) string {
	return "e-" + digest([]string{mailbox, strconv.FormatUint(uint64(validity), 10), strconv.FormatUint(uint64(uid), 10)})
}

func unreadEmail(keywords map[string]bool) bool {
	return !keywords["$seen"] && !keywords["$draft"]
}

func keywords(flags []imap.Flag) map[string]bool {
	out := make(map[string]bool)
	for _, flag := range flags {
		if name := keywordName(flag); name != "" {
			out[name] = true
		}
	}
	return out
}

func keywordName(flag imap.Flag) string {
	name := strings.ToLower(string(flag))
	switch name {
	case "\\seen", "\\answered", "\\flagged", "\\draft":
		return "$" + name[1:]
	case "$seen", "$answered", "$flagged", "$draft":
		return ""
	default:
		if validKeyword(string(flag)) {
			return name
		}
		return ""
	}
}

func validKeyword(s string) bool {
	return len(s) > 0 && len(s) <= 255 && strings.IndexFunc(s, func(r rune) bool {
		return r <= ' ' || r >= 127 || strings.ContainsRune("(){%*\"\\]", r)
	}) < 0
}

func (g *Gateway) connectIMAP(ctx context.Context) (*imapclient.Client, func(), error) {
	conn, closeConn, err := dial(ctx, g.config.IMAP.Address)
	if err != nil {
		return nil, closeConn, err
	}
	secured := tls.Client(conn, g.imapTLS)
	if err := secured.HandshakeContext(ctx); err != nil {
		closeConn()
		return nil, closeConn, err
	}
	client := imapclient.New(secured, &imapclient.Options{WordDecoder: &mime.WordDecoder{CharsetReader: charset.Reader}})
	closeClient := func() {
		closeConn()
		_ = client.Close()
	}
	if err := client.Login(g.config.IMAP.Username, g.config.IMAP.Password).Wait(); err != nil {
		closeClient()
		return nil, closeClient, err
	}
	return client, closeClient, nil
}

func hasAttr(attrs []imap.MailboxAttr, attr imap.MailboxAttr) bool {
	for _, item := range attrs {
		if strings.EqualFold(string(item), string(attr)) {
			return true
		}
	}
	return false
}

func supportedRole(data *imap.ListData, configuredDrafts string) string {
	if strings.EqualFold(data.Mailbox, "INBOX") {
		return "inbox"
	}
	if data.Mailbox == configuredDrafts {
		return "drafts"
	}
	for _, attr := range data.Attrs {
		switch strings.ToLower(string(attr)) {
		case "\\drafts":
			if configuredDrafts == "" {
				return "drafts"
			}
		case "\\sent", "\\trash", "\\junk", "\\archive", "\\all", "\\flagged":
			return strings.ToLower(string(attr))[1:]
		}
	}
	return ""
}

func (g *Gateway) scan(client *imapclient.Client) (*snapshot, string) {
	caps := client.Caps()
	if g.config.MailboxMetadataVendor != "" && !caps.Has(imap.CapMetadata) {
		return nil, "serverFail"
	}
	options := &imap.ListOptions{
		ReturnSpecialUse: caps.Has(imap.CapSpecialUse),
		ReturnSubscribed: caps.Has(imap.CapListExtended) || caps.Has(imap.CapIMAP4rev2),
	}
	list := client.List("", "*", options)
	defer list.Close()
	data := make([]*imap.ListData, 0)
	for item := list.Next(); item != nil; item = list.Next() {
		data = append(data, item)
		if len(data) > maxMailboxes {
			return nil, "serverFail"
		}
	}
	if err := list.Close(); err != nil {
		return nil, imapFailure(err)
	}
	sort.Slice(data, func(i, j int) bool { return data[i].Mailbox < data[j].Mailbox })

	state, failure := g.loadMailboxState()
	if failure != "" {
		return nil, failure
	}
	paths := make(map[string]bool, len(data))
	for _, item := range data {
		paths[item.Mailbox] = true
	}
	if failure := g.reconcileMailboxRename(client, &state, paths); failure != "" {
		return nil, failure
	}
	moves, failure := g.loadEmailMoves()
	if failure != "" {
		return nil, failure
	}
	s := &snapshot{emails: make(map[string]*emailMeta), paths: paths, mailboxes: state, moves: moves}
	boxes := make(map[string]*box)
	roles := make(map[string]bool)
	for _, item := range data {
		skip := false
		for _, attr := range item.Attrs {
			if strings.EqualFold(string(attr), "\\Noselect") || strings.EqualFold(string(attr), "\\NonExistent") {
				skip = true
			}
		}
		if skip {
			continue
		}
		path := item.Mailbox
		details := state.Details[path]
		id := details.ID
		if id == "" {
			id = mailboxID(g.config.AccountID, path)
		}
		role := supportedRole(item, g.config.DraftsMailbox)
		if roles[role] {
			role = ""
		}
		roles[role] = role != ""
		subscribed := hasAttr(item.Attrs, imap.MailboxAttrSubscribed)
		if !options.ReturnSubscribed {
			subscribed = details.Subscribed
		}
		b := &box{ID: id, Path: path, Name: path, Role: role, Subscribed: subscribed, Delimiter: item.Delim, SortOrder: details.SortOrder}
		if strings.EqualFold(path, "INBOX") {
			s.rootDelimiter = item.Delim
		}
		if item.Delim != 0 {
			if i := strings.LastIndex(path, string(item.Delim)); i >= 0 {
				b.Name = path[i+len(string(item.Delim)):]
				b.ParentID = path[:i]
			}
		}
		boxes[path] = b
		s.boxes = append(s.boxes, b)
	}
	if g.config.MailboxMetadataVendor != "" {
		if failure := g.trackMailboxIDs(client, &s.mailboxes, s.boxes, options.ReturnSubscribed); failure != "" {
			return nil, failure
		}
	}
	for _, b := range s.boxes {
		if parent := boxes[b.ParentID]; parent != nil {
			b.ParentID = parent.ID
		} else {
			b.ParentID = ""
		}
		protectPath := b.Role == "inbox" || b.Path == g.config.DraftsMailbox
		if caps.Has(imap.CapACL) {
			if failure := b.loadACL(client, protectPath, supportsUIDExpunge(caps)); failure != "" {
				return nil, failure
			}
			if !b.mayReadItems() {
				continue
			}
		}
		selected, err := client.Select(b.Path, nil).Wait()
		if err != nil {
			return nil, imapFailure(err)
		}
		v := selected.UIDValidity
		if v == 0 || b.Validity != 0 && b.Validity != v || int(selected.NumMessages) > maxMessages-len(s.emails) {
			return nil, "serverFail"
		}
		b.Validity = v
		b.NextUID = selected.UIDNext
		if b.ACL == nil {
			b.Writable = !selected.ReadOnly
			b.CanRemoveItems = b.Writable && supportsUIDExpunge(caps)
			b.CanCreateChild = b.Writable && b.Delimiter != 0
			b.CanChangePath = b.Writable && !protectPath
		} else if selected.ReadOnly {
			b.CanRemoveItems = false
			b.ACL.SetSeen = false
			b.ACL.SetKeywords = false
		}
		if selected.NumMessages == 0 {
			continue
		}
		var seq imap.SeqSet
		seq.AddRange(1, selected.NumMessages)
		section := &imap.FetchItemBodySection{Specifier: imap.PartSpecifierHeader, HeaderFields: threadHeaders,
			Peek: true, Partial: &imap.SectionPartial{Size: maxThreadHeaders}}
		messages, err := client.Fetch(seq, &imap.FetchOptions{
			UID: true, Flags: true, InternalDate: true, RFC822Size: true,
			BodySection: []*imap.FetchItemBodySection{section},
		}).Collect()
		if err != nil {
			return nil, imapFailure(err)
		}
		for _, msg := range messages {
			if msg.UID == 0 || msg.InternalDate.IsZero() || msg.RFC822Size < 0 {
				return nil, "serverFail"
			}
			if flagPresent(msg.Flags, imap.FlagDeleted) {
				continue
			}
			header := msg.FindBodySection(section)
			if header == nil {
				return nil, "serverFail"
			}
			e := &emailMeta{ID: moves.resolve(emailID(b.ID, v, msg.UID)), MailboxID: b.ID, Path: b.Path, Validity: v, UID: msg.UID,
				Received: msg.InternalDate.UTC(), Size: msg.RFC822Size, Keywords: keywords(msg.Flags),
				ThreadID: threadForMessage(g.config.AccountID, header)}
			s.emails[e.ID] = e
		}
	}
	if failure := g.reconcileEmailMove(s); failure != "" {
		return nil, failure
	}
	s.countMailboxes()
	return s, ""
}

func imapFailure(err error) string {
	var status *imap.Error
	if errors.As(err, &status) {
		return "serverFail"
	}
	return "serverUnavailable"
}

func selectEmail(client *imapclient.Client, email *emailMeta, readOnly bool) string {
	selected, err := client.Select(email.Path, &imap.SelectOptions{ReadOnly: readOnly}).Wait()
	if err != nil {
		return imapFailure(err)
	}
	if selected.UIDValidity != email.Validity {
		return "notFound"
	}
	if !readOnly && selected.ReadOnly {
		return "forbidden"
	}
	return ""
}

func fetchRaw(client *imapclient.Client, email *emailMeta) ([]byte, string) {
	if email.Size > maxRaw {
		return nil, "serverFail"
	}
	section := &imap.FetchItemBodySection{Peek: true, Partial: &imap.SectionPartial{Size: maxRaw + 1}}
	return fetchEmailSection(client, email, section, maxRaw)
}

func fetchEmailSection(client *imapclient.Client, email *emailMeta, section *imap.FetchItemBodySection, limit int) ([]byte, string) {
	if failure := selectEmail(client, email, true); failure != "" {
		return nil, failure
	}
	items, err := client.Fetch(imap.UIDSetNum(email.UID),
		&imap.FetchOptions{UID: true, BodySection: []*imap.FetchItemBodySection{section}}).Collect()
	if err != nil {
		return nil, imapFailure(err)
	}
	for _, item := range items {
		if item.UID == email.UID {
			raw := item.FindBodySection(section)
			if raw == nil || len(raw) > limit {
				return nil, "serverFail"
			}
			return raw, ""
		}
	}
	return nil, "notFound"
}

func appendEmail(client *imapclient.Client, mailbox *box, raw []byte, flags []imap.Flag, now time.Time) (*emailMeta, string) {
	if !mailbox.Writable || mailbox.ACL != nil && !mailbox.allowsKeywordChange(nil, keywordChange{values: keywords(flags)}) {
		return nil, "forbidden"
	}
	caps := client.Caps()
	if !caps.Has(imap.CapUIDPlus) && !caps.Has(imap.CapIMAP4rev2) {
		return nil, "serverFail"
	}
	cmd := client.Append(mailbox.Path, int64(len(raw)), &imap.AppendOptions{Flags: flags, Time: now})
	_, writeErr := cmd.Write(raw)
	closeErr := cmd.Close()
	added, err := cmd.Wait()
	if err != nil {
		return nil, imapFailure(err)
	}
	if writeErr != nil || closeErr != nil || added.UID == 0 || added.UIDValidity == 0 {
		return nil, "serverFail"
	}
	return &emailMeta{ID: emailID(mailbox.ID, added.UIDValidity, added.UID), MailboxID: mailbox.ID,
		Path: mailbox.Path, Validity: added.UIDValidity, UID: added.UID, Received: now,
		Size: int64(len(raw)), Keywords: keywords(flags)}, ""
}

func take(reader io.Reader, limit int64) ([]byte, bool, error) {
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if int64(len(data)) > limit {
		return data[:limit], true, err
	}
	return data, false, err
}
