package gateway

import (
	"encoding/json"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

type mailboxDetails struct {
	ID         string
	SortOrder  uint32
	Subscribed bool
}

type mailboxRenameEntry struct {
	From, To string
	Validity uint32
	Details  mailboxDetails
}

type mailboxState struct {
	Details     map[string]mailboxDetails
	Rename      []mailboxRenameEntry
	MetadataKey string
	MetadataIDs map[string]string
}

const mailboxStateFile = "mailboxes.json"

func (g *Gateway) loadMailboxState() (mailboxState, string) {
	file, err := os.Open(filepath.Join(g.config.StateDir, mailboxStateFile))
	if os.IsNotExist(err) {
		return mailboxState{Details: make(map[string]mailboxDetails)}, ""
	}
	if err != nil {
		return mailboxState{}, "serverFail"
	}
	defer file.Close()
	data, large, err := take(file, maxHistoryFile)
	var state mailboxState
	if err != nil || large || json.Unmarshal(data, &state) != nil || state.Details == nil {
		return mailboxState{}, "serverFail"
	}
	return state, ""
}

func (g *Gateway) saveMailboxState(state mailboxState) string {
	err := g.ledger.files.replace(g.config.StateDir, mailboxStateFile, ".mailboxes-*", func(w io.Writer) error {
		return json.NewEncoder(w).Encode(state)
	})
	if err != nil {
		return "serverFail"
	}
	return ""
}

func (g *Gateway) reconcileMailboxRename(client *imapclient.Client, state *mailboxState, paths map[string]bool) string {
	if len(state.Rename) == 0 {
		return ""
	}
	root := state.Rename[0]
	oldExists, newExists := paths[root.From], paths[root.To]
	if oldExists == newExists {
		return "serverFail"
	}
	if newExists {
		for _, entry := range state.Rename {
			status, err := client.Status(entry.To, &imap.StatusOptions{UIDValidity: true}).Wait()
			if err != nil || status.UIDValidity != entry.Validity {
				return "serverFail"
			}
		}
	}
	*state = state.finishRename(newExists)
	return g.saveMailboxState(*state)
}

func (state mailboxState) finishRename(applied bool) mailboxState {
	result := state
	result.Details, result.Rename = maps.Clone(state.Details), nil
	if applied {
		for _, entry := range state.Rename {
			// The old path can be reused by another IMAP mailbox.
			result.Details[entry.From] = mailboxDetails{ID: "m-" + randomID()}
			result.Details[entry.To] = entry.Details
		}
	}
	return result
}

func mailboxSubtree(root, candidate *box) bool {
	return root.ID == candidate.ID || root.Delimiter != 0 && strings.HasPrefix(candidate.Path, root.Path+string(root.Delimiter))
}
