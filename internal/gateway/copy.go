package gateway

import (
	"encoding/json"
	"errors"
)

func (op *operation) copyBlobs(raw rawObject) (object, string) {
	var args struct {
		accountArgs
		FromAccountID string   `json:"fromAccountId"`
		BlobIDs       []string `json:"blobIds"`
	}
	if !decodeArgs(raw, &args) || args.FromAccountID == "" || args.FromAccountID == args.AccountID || args.BlobIDs == nil {
		return nil, "invalidArguments"
	}
	if len(args.BlobIDs) > maxSet {
		return nil, "requestTooLarge"
	}
	source := op.forAccount(args.FromAccountID)
	if source == nil {
		return nil, "fromAccountNotFound"
	}
	copied, notCopied := object{}, object{}
	for _, requested := range args.BlobIDs {
		if copied[requested] != nil || notCopied[requested] != nil {
			continue
		}
		if id, code := op.copyBlob(source, source.resolveID(requested)); code != "" {
			notCopied[requested] = object{"type": code}
		} else {
			copied[requested] = id
		}
	}
	return object{"fromAccountId": args.FromAccountID, "copied": optionalSetMap(copied), "notCopied": optionalSetMap(notCopied)}, ""
}

func (op *operation) copyBlob(source *operation, id string) (string, string) {
	location, valid := locateBlob(id)
	if !valid {
		return "", "notFound"
	}
	raw, failure := source.readBlob(location)
	if failure != "" {
		return "", failure
	}
	id, err := op.g.uploads.put(raw)
	if errors.Is(err, errBlobQuota) {
		return "", "overQuota"
	}
	if err != nil {
		return "", "serverFail"
	}
	return id, ""
}

func (op *operation) copyEmails(raw rawObject) (object, string) {
	var args struct {
		accountArgs
		FromAccountID            string    `json:"fromAccountId"`
		IfFromInState            *string   `json:"ifFromInState"`
		IfInState                *string   `json:"ifInState"`
		Create                   rawObject `json:"create"`
		OnSuccessDestroyOriginal bool      `json:"onSuccessDestroyOriginal"`
		DestroyFromIfInState     *string   `json:"destroyFromIfInState"`
	}
	if !decodeArgs(raw, &args) || args.FromAccountID == "" || args.FromAccountID == args.AccountID || args.Create == nil {
		return nil, "invalidArguments"
	}
	if len(args.Create) > maxSet {
		return nil, "requestTooLarge"
	}
	for key := range args.Create {
		if !jmapID.MatchString(key) {
			return nil, "invalidArguments"
		}
	}
	source := op.forAccount(args.FromAccountID)
	if source == nil {
		return nil, "fromAccountNotFound"
	}
	if failure := source.loadMail(); failure != "" {
		return nil, failure
	}
	if args.IfFromInState != nil && source.state("Email") != *args.IfFromInState {
		return nil, "stateMismatch"
	}
	if failure := op.loadMail(); failure != "" {
		return nil, failure
	}
	oldState := op.state("Email")
	if args.IfInState != nil && *args.IfInState != oldState {
		return nil, "stateMismatch"
	}

	created, notCreated := object{}, object{}
	remove := make(map[string]bool)
	for _, key := range sortedKeys(args.Create) {
		copied, original, failure := op.copyEmail(source, args.Create[key])
		if failure != nil {
			notCreated[key] = failure
		} else {
			op.created[key] = copied.ID
			created[key] = createdEmail(copied)
			remove[original] = true
		}
	}
	if args.OnSuccessDestroyOriginal && len(remove) != 0 {
		ids, _ := json.Marshal(sortedKeys(remove))
		state, _ := json.Marshal(args.DestroyFromIfInState)
		op.implicit = source.implicitEmailSet(rawObject{"destroy": ids, "ifInState": state})
	}
	return object{"fromAccountId": args.FromAccountID, "oldState": oldState, "newState": op.state("Email"),
		"created": optionalSetMap(created), "notCreated": optionalSetMap(notCreated)}, ""
}

func (op *operation) copyEmail(source *operation, raw json.RawMessage) (*emailMeta, string, object) {
	var input struct {
		ID         string          `json:"id"`
		MailboxIDs map[string]bool `json:"mailboxIds"`
		Keywords   json.RawMessage `json:"keywords"`
		ReceivedAt json.RawMessage `json:"receivedAt"`
	}
	if !decodeStrict(raw, &input) || input.ID == "" {
		return nil, "", object{"type": "invalidProperties"}
	}
	id := source.resolveID(input.ID)
	original := source.snapshot.emails[id]
	if original == nil {
		return nil, "", object{"type": "notFound"}
	}
	if input.MailboxIDs == nil {
		input.MailboxIDs = map[string]bool{original.MailboxID: true}
	}
	if len(input.MailboxIDs) > 1 {
		return nil, "", object{"type": "tooManyMailboxes"}
	}
	var destination *box
	for requested, enabled := range input.MailboxIDs {
		if enabled {
			destination = op.snapshot.mailbox(op.resolveID(requested))
		}
	}
	if destination == nil {
		return nil, "", invalidProperty("mailboxIds")
	}
	keywords := original.Keywords
	if input.Keywords != nil {
		var replacement map[string]bool
		if !decodeStrict(input.Keywords, &replacement) || replacement == nil {
			return nil, "", invalidProperty("keywords")
		}
		keywords = replacement
	}
	flags, valid := importFlags(keywords)
	if !valid {
		return nil, "", invalidProperty("keywords")
	}
	received := original.Received
	if input.ReceivedAt != nil {
		var value string
		if !decodeStrict(input.ReceivedAt, &value) {
			return nil, "", invalidProperty("receivedAt")
		}
		received, valid = vacationDate(value)
		if !valid {
			return nil, "", invalidProperty("receivedAt")
		}
	}
	if len(op.snapshot.emails) >= maxMessages {
		return nil, "", object{"type": "overQuota"}
	}
	if original.Size > maxRaw {
		return nil, "", object{"type": "tooLarge", "maxSize": maxRaw}
	}
	message, failure := source.readRaw(original)
	if failure != "" {
		return nil, "", object{"type": failure}
	}
	copied, failure := appendEmail(op.client, destination, message, flags, received)
	if failure != "" {
		return nil, "", object{"type": failure}
	}
	copied.ThreadID = threadForMessage(op.g.config.AccountID, message)
	op.snapshot.recordAppend(destination, copied)
	return copied, id, nil
}

func invalidProperty(name string) object {
	return object{"type": "invalidProperties", "properties": []string{name}}
}
