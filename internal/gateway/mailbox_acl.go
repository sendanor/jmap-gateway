package gateway

import (
	"strings"

	"github.com/emersion/go-imap/v2/imapclient"
)

type mailboxACL struct {
	Read, SetSeen, SetKeywords, Submit bool
}

func (b *box) loadACL(client *imapclient.Client, protectPath, canExpunge bool) string {
	data, err := client.MyRights(b.Path).Wait()
	if err != nil {
		return imapFailure(err)
	}
	if data.Mailbox != b.Path && !(strings.EqualFold(data.Mailbox, "INBOX") && strings.EqualFold(b.Path, "INBOX")) {
		return "serverFail"
	}
	rights := data.Rights.String()
	has := func(right rune) bool { return strings.ContainsRune(rights, right) }
	read := has('l') && has('r')
	b.ACL = &mailboxACL{Read: read, SetSeen: read && has('s'), SetKeywords: read && has('w'), Submit: has('p')}

	// The gateway needs readable UID metadata to return durable JMAP IDs and
	// to reconcile a mailbox rename. A lookup-only mailbox may still be a parent.
	b.Writable = read && has('i')
	b.CanRemoveItems = read && canExpunge && has('t') && has('e')
	b.CanCreateChild = b.Delimiter != 0 && has('k')
	b.CanChangePath = read && !protectPath && has('x')
	return ""
}

func (b *box) mayReadItems() bool {
	return b == nil || b.ACL == nil || b.ACL.Read
}

func (b *box) allowsRemoval() bool {
	return b == nil || b.ACL == nil || b.CanRemoveItems
}

func (b *box) allowsKeywordChange(current map[string]bool, change keywordChange) bool {
	if b == nil || b.ACL == nil {
		return true
	}
	allowed := func(key string) bool {
		if key == "$seen" {
			return b.ACL.SetSeen
		}
		return b.ACL.SetKeywords
	}
	for key, present := range change.values {
		if current[key] != present && !allowed(key) {
			return false
		}
	}
	if change.replace {
		for key, present := range current {
			if present && !change.values[key] && !allowed(key) {
				return false
			}
		}
	}
	return true
}

func (b *box) mailboxRights() object {
	seen, keywords, submit := b.Writable, b.Writable, true
	if b.ACL != nil {
		seen, keywords, submit = b.ACL.SetSeen, b.ACL.SetKeywords, b.ACL.Submit
	}
	return object{
		"mayReadItems": b.mayReadItems(), "mayAddItems": b.Writable,
		"mayRemoveItems": b.CanRemoveItems, "maySetSeen": seen, "maySetKeywords": keywords,
		"mayCreateChild": b.CanCreateChild, "mayRename": b.CanChangePath, "mayDelete": b.CanChangePath, "maySubmit": submit,
	}
}
