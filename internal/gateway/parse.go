package gateway

import (
	"errors"
	"os"
	"regexp"
	"strings"
)

const maxNestedBlobParts = 4

var mimePartID = regexp.MustCompile(`^1(?:_[1-9][0-9]*)*$`)

type blobLocation struct {
	root       string
	parts      []string
	legacyText bool
}

func locateBlob(id string) (blobLocation, bool) {
	if len(id) < 45 || !jmapID.MatchString(id) {
		return blobLocation{}, false
	}
	switch id[0:2] {
	case "b-", "u-":
		return blobLocation{root: id}, len(id) == 45
	case "p-", "q-", "r-":
		if len(id) < 47 || id[45] != '-' {
			return blobLocation{}, false
		}
		parts := strings.Split(id[46:], "-")
		if len(parts) > maxNestedBlobParts {
			return blobLocation{}, false
		}
		for _, part := range parts {
			if !mimePartID.MatchString(part) {
				return blobLocation{}, false
			}
		}
		prefix := "b-"
		if id[0] == 'q' {
			prefix = "u-"
		}
		return blobLocation{root: prefix + id[2:45], parts: parts, legacyText: id[0] == 'p'}, true
	default:
		return blobLocation{}, false
	}
}

func (op *operation) readBlob(location blobLocation) ([]byte, string) {
	id := location.root
	var data []byte
	if id[0] == 'u' {
		bytes, err := op.g.uploads.read(id)
		switch {
		case errors.Is(err, os.ErrNotExist):
			return nil, "notFound"
		case err != nil:
			return nil, "serverUnavailable"
		}
		budget := op.requestOperation()
		budget.rawBytes += int64(len(bytes))
		if budget.rawBytes > 12*maxRaw {
			return nil, "requestTooLarge"
		}
		data = bytes
	} else {
		if failure := op.loadMail(); failure != "" {
			return nil, failure
		}
		email := op.snapshot.emails["e-"+id[2:]]
		if email == nil {
			return nil, "notFound"
		}
		raw, failure := op.readRaw(email)
		if failure != "" {
			return nil, failure
		}
		data = raw
	}
	for _, part := range location.parts {
		message, failure := parseMIME(data, id)
		if failure != "" || message.parts[part] == nil {
			return nil, "notFound"
		}
		data = message.parts[part].Octets
		if location.legacyText {
			data = message.parts[part].Value
		}
		id = partBlobID(id, part)
	}
	return data, ""
}

var defaultParseProperties = []string{
	"messageId", "inReplyTo", "references", "sender", "from", "to", "cc", "bcc",
	"replyTo", "subject", "sentAt", "hasAttachment", "preview", "bodyValues",
	"textBody", "htmlBody", "attachments",
}

func (op *operation) parseEmails(raw rawObject) (object, string) {
	var args struct {
		getArgs
		BlobIDs []string `json:"blobIds"`
	}
	if !decodeArgs(raw, &args) || args.BlobIDs == nil || raw["ids"] != nil || args.MaxBodyValueBytes < 0 {
		return nil, "invalidArguments"
	}
	if len(args.BlobIDs) > maxGet {
		return nil, "requestTooLarge"
	}
	if args.Properties == nil {
		args.Properties = defaultParseProperties
	}
	if !args.prepareHeaderProjections() {
		return nil, "invalidArguments"
	}

	var parsed object
	var notParsable, notFound []string
	seen := make(map[string]bool)
	for _, requested := range args.BlobIDs {
		if seen[requested] {
			continue
		}
		seen[requested] = true
		id := op.resolveID(requested)
		location, valid := locateBlob(id)
		if !valid {
			notFound = append(notFound, requested)
			continue
		}
		data, failure := op.readBlob(location)
		switch failure {
		case "notFound":
			notFound = append(notFound, requested)
			continue
		case "":
		default:
			return nil, failure
		}
		message, failure := parseMIME(data, id)
		if failure != "" || len(message.header) == 0 || len(location.parts) >= maxNestedBlobParts {
			notParsable = append(notParsable, requested)
			continue
		}
		record := message.messageRecord(args.getArgs)
		record["blobId"], record["size"] = id, len(data)
		record["mailboxIds"], record["keywords"], record["receivedAt"], record["threadId"] = nil, nil, nil, nil
		if contains(args.Properties, "id") {
			record["id"] = nil
		}
		if parsed == nil {
			parsed = make(object)
		}
		parsed[id] = project(record, args.Properties)
	}
	return object{"parsed": parsed, "notParsable": notParsable, "notFound": notFound}, ""
}
