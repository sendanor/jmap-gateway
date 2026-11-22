package gateway

import (
	"errors"
	"maps"
	"slices"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

type keywordChange struct {
	replace bool
	values  map[string]bool
}

func keywordPatch(patch rawObject) (keywordChange, bool) {
	change := keywordChange{values: make(map[string]bool)}
	if raw, ok := patch["keywords"]; ok {
		var keywords map[string]bool
		if len(patch) != 1 || !decodeStrict(raw, &keywords) {
			return keywordChange{}, false
		}
		change.replace = true
		for key, present := range keywords {
			if !present || !change.add(key, true) {
				return keywordChange{}, false
			}
		}
		return change, true
	}
	for path, raw := range patch {
		key, ok := strings.CutPrefix(path, "keywords/")
		if !ok || strings.ContainsRune(key, '/') || !validPointerToken(key) {
			return keywordChange{}, false
		}
		var value *bool
		if !decodeStrict(raw, &value) || value != nil && !*value ||
			!change.add(strings.NewReplacer("~1", "/", "~0", "~").Replace(key), value != nil) {
			return keywordChange{}, false
		}
	}
	return change, true
}

func validPointerToken(value string) bool {
	for index := strings.IndexByte(value, '~'); index >= 0; index = strings.IndexByte(value, '~') {
		if index+1 == len(value) || value[index+1] != '0' && value[index+1] != '1' {
			return false
		}
		value = value[index+2:]
	}
	return true
}

func (change keywordChange) add(key string, value bool) bool {
	if !validKeyword(key) {
		return false
	}
	key = strings.ToLower(key)
	if _, duplicate := change.values[key]; duplicate {
		return false
	}
	change.values[key] = value
	return true
}

func keywordFlag(name string) imap.Flag {
	switch name {
	case "$seen":
		return imap.FlagSeen
	case "$answered":
		return imap.FlagAnswered
	case "$flagged":
		return imap.FlagFlagged
	case "$draft":
		return imap.FlagDraft
	default:
		return imap.Flag(name)
	}
}

func (op *operation) applyEmailKeywords(email *emailMeta, change keywordChange) string {
	if !change.replace && len(change.values) == 0 {
		return ""
	}
	flags, failure := storeEmailKeywords(op.client, email, change)
	if failure == "notFound" {
		op.snapshot.forgetEmail(email.ID)
	} else if flags != nil {
		unreadChanged := unreadEmail(email.Keywords) != unreadEmail(flags)
		email.Keywords = flags
		if unreadChanged {
			op.snapshot.countMailboxes()
		}
	}
	return failure
}

func (s *snapshot) forgetEmail(id string) {
	delete(s.emails, id)
	s.countMailboxes()
}

func storeEmailKeywords(client *imapclient.Client, email *emailMeta, change keywordChange) (map[string]bool, string) {
	if failure := selectEmail(client, email, false); failure != "" {
		return nil, failure
	}
	uid := imap.UIDSetNum(email.UID)
	var add, remove []imap.Flag
	for _, key := range sortedKeys(change.values) {
		if change.values[key] {
			add = append(add, keywordFlag(key))
		} else {
			remove = append(remove, keywordFlag(key))
		}
	}
	operation, flags := imap.StoreFlagsAdd, add
	switch {
	case change.replace || len(add) != 0 && len(remove) != 0:
		current, failure := fetchEmailFlags(client, email.UID)
		if failure != "" || flagPresent(current, imap.FlagDeleted) {
			return nil, hiddenEmailFailure(failure)
		}
		operation, flags = imap.StoreFlagsSet, replacementFlags(current, change)
	case len(remove) != 0:
		operation, flags = imap.StoreFlagsDel, remove
	}
	if err := storeEmailFlags(client, uid, operation, flags); err != nil {
		return nil, emailMutationFailure(err, true)
	}
	observed, failure := fetchEmailFlags(client, email.UID)
	if failure != "" || flagPresent(observed, imap.FlagDeleted) {
		return nil, hiddenEmailFailure(failure)
	}
	values := keywords(observed)
	if change.replace && !maps.Equal(values, change.values) {
		return values, "forbidden"
	}
	for key, want := range change.values {
		if values[key] != want {
			return values, "forbidden"
		}
	}
	return values, ""
}

func replacementFlags(current []imap.Flag, change keywordChange) []imap.Flag {
	flags := make([]imap.Flag, 0, len(current)+len(change.values))
	values := make(map[string]bool)
	for _, flag := range current {
		if key := keywordName(flag); key != "" {
			if !change.replace {
				values[key] = true
			}
		} else if !strings.EqualFold(string(flag), `\Recent`) {
			flags = append(flags, flag)
		}
	}
	maps.Copy(values, change.values)
	for _, key := range sortedKeys(values) {
		if values[key] {
			flags = append(flags, keywordFlag(key))
		}
	}
	return flags
}

func hiddenEmailFailure(failure string) string {
	if failure != "" {
		return failure
	}
	return "notFound"
}

func fetchEmailFlags(client *imapclient.Client, uid imap.UID) ([]imap.Flag, string) {
	items, err := client.Fetch(imap.UIDSetNum(uid), &imap.FetchOptions{UID: true, Flags: true}).Collect()
	if err != nil {
		return nil, imapFailure(err)
	}
	for _, item := range items {
		if item.UID == uid {
			return item.Flags, ""
		}
	}
	return nil, "notFound"
}

func storeEmailFlags(client *imapclient.Client, uid imap.UIDSet, operation imap.StoreFlagsOp, flags []imap.Flag) error {
	return client.Store(uid, &imap.StoreFlags{Op: operation, Silent: true, Flags: flags}, nil).Close()
}

func flagPresent(flags []imap.Flag, target imap.Flag) bool {
	return slices.ContainsFunc(flags, func(flag imap.Flag) bool { return strings.EqualFold(string(flag), string(target)) })
}

func emailMutationFailure(err error, changingKeywords bool) string {
	var reply *imap.Error
	if errors.As(err, &reply) {
		switch reply.Code {
		case imap.ResponseCodeNoPerm:
			return "forbidden"
		case imap.ResponseCodeLimit:
			if changingKeywords {
				return "tooManyKeywords"
			}
		}
	}
	return imapFailure(err)
}

func supportsUIDExpunge(caps imap.CapSet) bool {
	return caps.Has(imap.CapUIDPlus) || caps.Has(imap.CapIMAP4rev2)
}

func (op *operation) destroyEmail(id string) string {
	email := op.snapshot.emails[id]
	if email == nil {
		return "notFound"
	}
	if op.client == nil || !op.snapshot.mailbox(email.MailboxID).allowsRemoval() || !supportsUIDExpunge(op.client.Caps()) {
		return "forbidden"
	}
	hidden, failure := expungeEmail(op.client, email)
	if hidden {
		op.snapshot.forgetEmail(id)
	}
	return failure
}

func expungeEmail(client *imapclient.Client, email *emailMeta) (bool, string) {
	if failure := selectEmail(client, email, false); failure != "" {
		return failure == "notFound", failure
	}
	uid := imap.UIDSetNum(email.UID)
	before, failure := fetchEmailFlags(client, email.UID)
	if failure != "" {
		return failure == "notFound", failure
	}
	marked := flagPresent(before, imap.FlagDeleted)
	if !marked {
		if err := storeEmailFlags(client, uid, imap.StoreFlagsAdd, []imap.Flag{imap.FlagDeleted}); err != nil {
			return false, emailMutationFailure(err, false)
		}
		after, failure := fetchEmailFlags(client, email.UID)
		if failure != "" {
			// STORE succeeded. Until a fresh scan proves otherwise, keep the
			// message out of this response batch if it may now be deleted.
			return true, failure
		}
		if !flagPresent(after, imap.FlagDeleted) {
			return false, "forbidden"
		}
	}
	if err := client.UIDExpunge(uid).Close(); err != nil {
		var reply *imap.Error
		if !marked && errors.As(err, &reply) {
			// Restore visibility only after a definite failure and only for
			// a deletion mark added by this request.
			if err := storeEmailFlags(client, uid, imap.StoreFlagsDel, []imap.Flag{imap.FlagDeleted}); err == nil {
				observed, failure := fetchEmailFlags(client, email.UID)
				if failure == "" && !flagPresent(observed, imap.FlagDeleted) {
					return false, emailMutationFailure(reply, false)
				}
			}
		}
		return true, emailMutationFailure(err, false)
	}
	observed, failure := fetchEmailFlags(client, email.UID)
	if failure == "notFound" {
		return true, ""
	}
	if failure != "" {
		return true, failure
	}
	return flagPresent(observed, imap.FlagDeleted), "serverFail"
}
