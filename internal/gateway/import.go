package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/mail"
	"os"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
)

func (op *operation) importEmails(raw rawObject) (object, string) {
	var args struct {
		accountArgs
		IfInState *string   `json:"ifInState"`
		Emails    rawObject `json:"emails"`
	}
	if !decodeArgs(raw, &args) || args.Emails == nil {
		return nil, "invalidArguments"
	}
	if len(args.Emails) > maxSet {
		return nil, "requestTooLarge"
	}
	for key := range args.Emails {
		if !jmapID.MatchString(key) {
			return nil, "invalidArguments"
		}
	}
	if failure := op.loadMail(); failure != "" {
		return nil, failure
	}
	oldState := op.state("Email")
	if args.IfInState != nil && *args.IfInState != oldState {
		return nil, "stateMismatch"
	}
	var created, notCreated object
	for _, key := range sortedKeys(args.Emails) {
		email, failure := op.importEmail(args.Emails[key])
		if failure != nil {
			if notCreated == nil {
				notCreated = make(object)
			}
			notCreated[key] = failure
			continue
		}
		if created == nil {
			created = make(object)
		}
		op.created[key] = email.ID
		created[key] = createdEmail(email)
	}
	return object{"oldState": oldState, "newState": op.state("Email"), "created": created, "notCreated": notCreated}, ""
}

func (op *operation) importEmail(raw json.RawMessage) (*emailMeta, object) {
	invalid := func(property string) object {
		return object{"type": "invalidProperties", "properties": []string{property}}
	}
	var input struct {
		BlobID     string          `json:"blobId"`
		MailboxIDs map[string]bool `json:"mailboxIds"`
		Keywords   map[string]bool `json:"keywords"`
		ReceivedAt *string         `json:"receivedAt"`
	}
	if !decodeStrict(raw, &input) {
		return nil, object{"type": "invalidProperties"}
	}
	id := op.resolveID(input.BlobID)
	if !strings.HasPrefix(id, "u-") || len(id) != 45 || !jmapID.MatchString(id) {
		return nil, invalid("blobId")
	}
	if len(input.MailboxIDs) != 1 {
		return nil, invalid("mailboxIds")
	}
	var folder *box
	for key, enabled := range input.MailboxIDs {
		if enabled {
			id := op.resolveID(key)
			for _, mailbox := range op.snapshot.boxes {
				if mailbox.ID == id {
					folder = mailbox
					break
				}
			}
		}
	}
	if folder == nil {
		return nil, invalid("mailboxIds")
	}
	flags, valid := importFlags(input.Keywords)
	if !valid {
		return nil, invalid("keywords")
	}
	if len(op.snapshot.emails) >= maxMessages {
		return nil, object{"type": "overQuota"}
	}
	contents, err := op.g.uploads.read(id)
	if errors.Is(err, os.ErrNotExist) {
		return nil, invalid("blobId")
	}
	if err != nil {
		return nil, object{"type": "serverUnavailable"}
	}
	parsed, err := mail.ReadMessage(bytes.NewReader(contents))
	if err != nil || len(parsed.Header) == 0 || bytes.IndexByte(contents, 0) >= 0 {
		return nil, object{"type": "invalidEmail"}
	}
	at, ok := importDate(parsed.Header, input.ReceivedAt, time.Now())
	if !ok {
		return nil, invalid("receivedAt")
	}
	result, failure := appendEmail(op.client, folder, contents, flags, at)
	if failure != "" {
		return nil, object{"type": failure}
	}
	result.ThreadID = threadForMessage(op.g.config.AccountID, contents)
	op.snapshot.recordAppend(folder, result)
	return result, nil
}

func importDate(header mail.Header, specified *string, now time.Time) (time.Time, bool) {
	if specified != nil {
		value, err := time.Parse(time.RFC3339, *specified)
		return value.Truncate(time.Second), err == nil && strings.HasSuffix(*specified, "Z")
	}
	for _, received := range header["Received"] {
		if semicolon := strings.LastIndexByte(received, ';'); semicolon >= 0 {
			if value, err := mail.ParseDate(strings.TrimSpace(received[semicolon+1:])); err == nil {
				return value.UTC().Truncate(time.Second), true
			}
		}
	}
	return now.UTC().Truncate(time.Second), true
}

func importFlags(values map[string]bool) ([]imap.Flag, bool) {
	flags := make([]imap.Flag, 0, len(values))
	for _, keyword := range sortedKeys(values) {
		name := strings.ToLower(keyword)
		if !values[keyword] || !validKeyword(keyword) {
			return nil, false
		}
		flags = append(flags, keywordFlag(name))
	}
	return flags, true
}
