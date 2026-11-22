package gateway

import (
	"encoding/json"
	"errors"
	"maps"
	"strings"
	"unicode"

	"github.com/emersion/go-imap/v2"
	"golang.org/x/text/unicode/norm"
)

const maxMailboxName = 255

func (op *operation) setMailboxes(raw rawObject) (object, string) {
	var args struct {
		accountArgs
		IfInState             *string   `json:"ifInState"`
		Create                rawObject `json:"create"`
		Update                rawObject `json:"update"`
		Destroy               []string  `json:"destroy"`
		OnDestroyRemoveEmails bool      `json:"onDestroyRemoveEmails"`
	}
	if !decodeArgs(raw, &args) {
		return nil, "invalidArguments"
	}
	if len(args.Create)+len(args.Update)+len(args.Destroy) > maxSet {
		return nil, "requestTooLarge"
	}
	for key := range args.Create {
		if !jmapID.MatchString(key) {
			return nil, "invalidArguments"
		}
	}
	if failure := op.loadMail(); failure != "" {
		return nil, failure
	}
	old := op.state("Mailbox")
	if args.IfInState != nil && *args.IfInState != old {
		return nil, "stateMismatch"
	}
	created, updated, notCreated, notUpdated, notDestroyed := object{}, object{}, object{}, object{}, object{}
	var destroyed []string
	for len(args.Create) > 0 {
		progress := false
		for _, key := range sortedKeys(args.Create) {
			var patch rawObject
			var parent string
			if decodeStrict(args.Create[key], &patch) && decodeStrict(patch["parentId"], &parent) &&
				strings.HasPrefix(parent, "#") && args.Create[parent[1:]] != nil {
				continue
			}
			progress = true
			delete(args.Create, key)
			id, failure := op.createMailbox(patch)
			if failure != nil {
				notCreated[key] = failure
			} else {
				op.created[key] = id
				created[key] = mailboxRecord(op.snapshot.mailbox(id))
			}
			if op.snapshotFailure != "" {
				return nil, op.snapshotFailure
			}
		}
		if !progress {
			for key := range args.Create {
				notCreated[key] = invalidMailboxProperty("parentId")
			}
			break
		}
	}
	for _, key := range sortedKeys(args.Update) {
		id := op.resolveID(key)
		if failure := op.updateMailbox(id, args.Update[key]); failure != nil {
			notUpdated[key] = failure
		} else {
			updated[id] = nil
		}
		if op.snapshotFailure != "" {
			return nil, op.snapshotFailure
		}
	}
	for _, key := range args.Destroy {
		id := op.resolveID(key)
		if failure := op.destroyMailbox(id, args.OnDestroyRemoveEmails); failure != nil {
			notDestroyed[key] = failure
		} else {
			destroyed = append(destroyed, id)
		}
		if op.snapshotFailure != "" {
			return nil, op.snapshotFailure
		}
	}
	return object{"oldState": old, "newState": op.state("Mailbox"), "created": optionalSetMap(created),
		"updated": optionalSetMap(updated), "destroyed": destroyed, "notCreated": optionalSetMap(notCreated),
		"notUpdated": optionalSetMap(notUpdated), "notDestroyed": optionalSetMap(notDestroyed)}, ""
}

func optionalSetMap(result object) object {
	if len(result) == 0 {
		return nil
	}
	return result
}

func invalidMailboxProperty(name string) object {
	return object{"type": "invalidProperties", "properties": []string{name}}
}

type mailboxUpdate struct {
	name, path, role string
	delimiter        rune
	parent           *box
	order            uint32
	subscribed       bool
}

func (s *snapshot) mailbox(id string) *box {
	for _, b := range s.boxes {
		if b.ID == id {
			return b
		}
	}
	return nil
}

func (op *operation) mailboxUpdate(b *box, patch rawObject) (mailboxUpdate, object) {
	change := mailboxUpdate{subscribed: true}
	if b != nil {
		change.name, change.role, change.order, change.subscribed = b.Name, b.Role, b.SortOrder, b.Subscribed
		change.parent = op.snapshot.mailbox(b.ParentID)
	}
	for _, key := range sortedKeys(patch) {
		raw := patch[key]
		switch key {
		case "name":
			if !decodeStrict(raw, &change.name) || string(raw) == "null" {
				return change, invalidMailboxProperty(key)
			}
		case "parentId", "role":
			var value *string
			if !decodeStrict(raw, &value) {
				return change, invalidMailboxProperty(key)
			}
			if key == "parentId" {
				change.parent = nil
				if value != nil {
					change.parent = op.snapshot.mailbox(op.resolveID(*value))
					if change.parent == nil || b != nil && mailboxSubtree(b, change.parent) {
						return change, invalidMailboxProperty(key)
					}
				}
			} else {
				change.role = ""
				if value != nil {
					change.role = *value
					if change.role == "" {
						return change, invalidMailboxProperty(key)
					}
				}
			}
		case "sortOrder":
			var value *uint32
			if !decodeStrict(raw, &value) || value == nil || *value >= 1<<31 {
				return change, invalidMailboxProperty(key)
			}
			change.order = *value
		case "isSubscribed":
			var value *bool
			if !decodeStrict(raw, &value) || value == nil {
				return change, invalidMailboxProperty(key)
			}
			change.subscribed = *value
		default:
			return change, invalidMailboxProperty(key)
		}
	}
	change.delimiter = op.snapshot.rootDelimiter
	if change.parent != nil {
		change.delimiter = change.parent.Delimiter
	}
	if strings.TrimSpace(change.name) == "" || len(change.name) > maxMailboxName || !norm.NFC.IsNormalString(change.name) ||
		strings.IndexFunc(change.name, unicode.IsControl) >= 0 || strings.ContainsRune(change.name, change.delimiter) {
		return change, invalidMailboxProperty("name")
	}
	change.path = change.name
	if b != nil && patch["name"] == nil && patch["parentId"] == nil {
		change.path = b.Path
	} else if change.parent != nil {
		change.path = change.parent.Path + string(change.delimiter) + change.name
	}
	if b == nil || change.path != b.Path {
		if change.parent != nil && !change.parent.CanCreateChild {
			return change, object{"type": "forbidden"}
		}
		if strings.EqualFold(change.path, "INBOX") || op.snapshot.paths[change.path] {
			return change, invalidMailboxProperty("name")
		}
	}
	return change, nil
}

func (op *operation) createMailbox(patch rawObject) (string, object) {
	change, failure := op.mailboxUpdate(nil, patch)
	if failure != nil {
		return "", failure
	}
	if len(op.snapshot.paths) >= maxMailboxes {
		return "", object{"type": "overQuota"}
	}
	var options imap.CreateOptions
	if change.role != "" {
		attrs := map[string]imap.MailboxAttr{"all": imap.MailboxAttrAll, "archive": imap.MailboxAttrArchive,
			"drafts": imap.MailboxAttrDrafts, "flagged": imap.MailboxAttrFlagged, "junk": imap.MailboxAttrJunk,
			"sent": imap.MailboxAttrSent, "trash": imap.MailboxAttrTrash}
		attr := attrs[change.role]
		if attr == "" || !op.client.Caps().Has(imap.CapCreateSpecialUse) ||
			change.role == "drafts" && op.g.config.DraftsMailbox != "" && change.path != op.g.config.DraftsMailbox {
			return "", invalidMailboxProperty("role")
		}
		for _, b := range op.snapshot.boxes {
			if b.Role == change.role {
				return "", invalidMailboxProperty("role")
			}
		}
		options.SpecialUse = []imap.MailboxAttr{attr}
	}
	if err := op.client.Create(change.path, &options).Wait(); err != nil {
		return "", mailboxIMAPError(err)
	}
	id := "m-" + randomID()
	state := op.snapshot.mailboxes
	state.Details[change.path] = mailboxDetails{ID: id, SortOrder: change.order}
	if err := op.setMailboxSubscription(change.path, change.subscribed); err != nil {
		return "", op.finishMailboxMutation(state, mailboxIMAPError(err))
	}
	details := state.Details[change.path]
	details.Subscribed = change.subscribed
	state.Details[change.path] = details
	if failure := op.finishMailboxMutation(state, nil); failure != nil {
		return "", failure
	}
	if op.snapshot.mailbox(id) == nil {
		return "", object{"type": "serverFail"}
	}
	return id, nil
}

func (op *operation) updateMailbox(id string, input json.RawMessage) object {
	b := op.snapshot.mailbox(id)
	if b == nil {
		return object{"type": "notFound"}
	}
	var patch rawObject
	if !decodeStrict(input, &patch) || patch == nil {
		return object{"type": "invalidPatch"}
	}
	change, failure := op.mailboxUpdate(b, patch)
	if failure != nil {
		return failure
	}
	if change.role != b.Role {
		return invalidMailboxProperty("role")
	}
	if change.path != b.Path {
		if !b.CanChangePath {
			return object{"type": "forbidden"}
		}
		return op.renameMailbox(b, change)
	}
	if change.subscribed == b.Subscribed && change.order == b.SortOrder {
		return nil
	}
	if change.subscribed != b.Subscribed {
		if err := op.setMailboxSubscription(b.Path, change.subscribed); err != nil {
			return mailboxIMAPError(err)
		}
	}
	state := op.snapshot.mailboxes
	state.Details[b.Path] = mailboxDetails{ID: b.ID, SortOrder: change.order, Subscribed: change.subscribed}
	return op.finishMailboxMutation(state, nil)
}

func (op *operation) renameMailbox(b *box, change mailboxUpdate) object {
	state := op.snapshot.mailboxes
	state.Rename = []mailboxRenameEntry{{From: b.Path, To: change.path, Validity: b.Validity,
		Details: mailboxDetails{ID: b.ID, SortOrder: change.order, Subscribed: change.subscribed}}}
	for _, child := range op.snapshot.boxes {
		if child.ID == b.ID || !mailboxSubtree(b, child) {
			continue
		}
		target := change.path + strings.TrimPrefix(child.Path, b.Path)
		if b.Delimiter != change.delimiter || op.snapshot.paths[target] {
			return invalidMailboxProperty("parentId")
		}
		state.Rename = append(state.Rename, mailboxRenameEntry{From: child.Path, To: target, Validity: child.Validity,
			Details: mailboxDetails{ID: child.ID, SortOrder: child.SortOrder, Subscribed: child.Subscribed}})
	}
	if failure := op.g.saveMailboxState(state); failure != "" {
		return object{"type": failure}
	}
	if err := op.client.Rename(b.Path, change.path, nil).Wait(); err != nil {
		var reply *imap.Error
		if !errors.As(err, &reply) {
			// The pending operation is resolved by checking UIDVALIDITY on
			// the next fresh connection. Never replay an ambiguous rename.
			op.snapshot, op.snapshotFailure = nil, "serverUnavailable"
			return object{"type": "serverUnavailable"}
		}
		return op.finishMailboxMutation(state.finishRename(false), mailboxIMAPError(err))
	}
	var failure object
	for _, entry := range state.Rename {
		if err := op.setMailboxSubscription(entry.To, entry.Details.Subscribed); err != nil {
			failure = mailboxIMAPError(err)
		}
	}
	return op.finishMailboxMutation(state.finishRename(true), failure)
}

func (op *operation) setMailboxSubscription(path string, subscribe bool) error {
	if subscribe {
		return op.client.Subscribe(path).Wait()
	}
	return op.client.Unsubscribe(path).Wait()
}

func (op *operation) destroyMailbox(id string, removeEmails bool) object {
	b := op.snapshot.mailbox(id)
	if b == nil {
		return object{"type": "notFound"}
	}
	if !b.CanChangePath {
		return object{"type": "forbidden"}
	}
	for path := range op.snapshot.paths {
		if b.Delimiter != 0 && strings.HasPrefix(path, b.Path+string(b.Delimiter)) {
			return object{"type": "mailboxHasChild"}
		}
	}
	status, err := op.client.Status(b.Path, &imap.StatusOptions{NumMessages: !removeEmails, UIDValidity: true}).Wait()
	if err != nil {
		return mailboxIMAPError(err)
	}
	if status.UIDValidity != b.Validity || !removeEmails && status.NumMessages == nil {
		return object{"type": "serverFail"}
	}
	if !removeEmails && *status.NumMessages > 0 {
		return object{"type": "mailboxHasEmail"}
	}
	if err := op.client.Delete(b.Path).Wait(); err != nil {
		return mailboxIMAPError(err)
	}
	state := op.snapshot.mailboxes
	state.Details = maps.Clone(state.Details)
	state.Details[b.Path] = mailboxDetails{ID: "m-" + randomID()}
	return op.finishMailboxMutation(state, nil)
}

func (op *operation) finishMailboxMutation(state mailboxState, failure object) object {
	if saved := op.g.saveMailboxState(state); saved != "" {
		failure = object{"type": saved}
	}
	op.snapshot, op.snapshotFailure = op.g.scan(op.client)
	if op.snapshotFailure != "" {
		return object{"type": op.snapshotFailure}
	}
	return failure
}

func mailboxIMAPError(err error) object {
	var reply *imap.Error
	if !errors.As(err, &reply) {
		return object{"type": "serverUnavailable"}
	}
	switch reply.Code {
	case imap.ResponseCodeAlreadyExists:
		return invalidMailboxProperty("name")
	case imap.ResponseCodeOverQuota:
		return object{"type": "overQuota"}
	case imap.ResponseCodeNonExistent:
		return object{"type": "notFound"}
	case imap.ResponseCodeNoPerm:
		return object{"type": "forbidden"}
	default:
		return object{"type": "serverFail"}
	}
}
