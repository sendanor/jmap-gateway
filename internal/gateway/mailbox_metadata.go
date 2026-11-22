package gateway

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"maps"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

func (g *Gateway) mailboxMetadataKey() string {
	account := sha256.Sum256([]byte(g.config.AccountID))
	return fmt.Sprintf("/private/vendor/%s/jmap-gateway/%x/mailbox-id", strings.ToLower(g.config.MailboxMetadataVendor), account)
}

func (g *Gateway) signMailboxID(id string) string {
	return g.signCursor("mailbox-id." + id)
}

func (g *Gateway) trackMailboxIDs(client *imapclient.Client, state *mailboxState, boxes []*box, upstreamSubscriptions bool) string {
	key := g.mailboxMetadataKey()
	if state.MetadataKey != "" && state.MetadataKey != key {
		return "serverFail"
	}
	ids := make(map[string]string, len(boxes))
	seen := make(map[string]bool, len(boxes))
	unmarked := make([]*box, 0)
	byID := make(map[string]mailboxDetails, len(state.Details))
	details := maps.Clone(state.Details)
	for path, value := range state.Details {
		byID[value.ID] = value
		if state.MetadataIDs[path] != "" {
			delete(details, path)
		}
	}
	for _, mailbox := range boxes {
		// IMAP can copy INBOX metadata on RENAME while keeping INBOX itself.
		if mailbox.Role == "inbox" {
			continue
		}
		// Initialize the mailbox instance before reading its annotation. A
		// recreated Maildir can otherwise briefly return the previous GUID's
		// METADATA until the server opens the new mailbox.
		status, err := client.Status(mailbox.Path, &imap.StatusOptions{UIDValidity: true}).Wait()
		if err != nil {
			return imapFailure(err)
		}
		if status.UIDValidity == 0 {
			return "serverFail"
		}
		mailbox.Validity = status.UIDValidity
		data, err := client.GetMetadata(mailbox.Path, []string{key}, nil).Wait()
		if err != nil {
			return imapFailure(err)
		}
		var value *[]byte
		for entry, stored := range data.Entries {
			if strings.EqualFold(entry, key) {
				value = stored
				break
			}
		}
		if value == nil {
			// Bind existing IDs on first use, and respect freshly created JMAP
			// mailboxes. An unmarked replacement for a tracked path is new.
			if state.MetadataIDs != nil && (state.MetadataIDs[mailbox.Path] != "" || state.Details[mailbox.Path].ID == "") {
				mailbox.ID = "m-" + randomID()
			}
			unmarked = append(unmarked, mailbox)
		} else {
			if len(*value) > 299 {
				return "serverFail"
			}
			id, signature, ok := strings.Cut(string(*value), ".")
			if !ok || !strings.HasPrefix(id, "m-") || !jmapID.MatchString(id) ||
				!hmac.Equal([]byte(signature), []byte(g.signMailboxID(id))) {
				return "serverFail"
			}
			mailbox.ID = id
		}
		if seen[mailbox.ID] {
			return "serverFail"
		}
		seen[mailbox.ID] = true
		ids[mailbox.Path] = mailbox.ID
		properties := byID[mailbox.ID]
		properties.ID = mailbox.ID
		mailbox.SortOrder = properties.SortOrder
		if !upstreamSubscriptions {
			mailbox.Subscribed = properties.Subscribed
		}
		details[mailbox.Path] = properties
	}
	for _, mailbox := range unmarked {
		value := []byte(mailbox.ID + "." + g.signMailboxID(mailbox.ID))
		if err := client.SetMetadata(mailbox.Path, map[string]*[]byte{key: &value}).Wait(); err != nil {
			return imapFailure(err)
		}
	}
	if state.MetadataKey == "" || !maps.Equal(state.MetadataIDs, ids) || !maps.Equal(state.Details, details) {
		state.MetadataKey, state.MetadataIDs, state.Details = key, ids, details
		return g.saveMailboxState(*state)
	}
	return ""
}
