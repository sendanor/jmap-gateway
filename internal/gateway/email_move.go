package gateway

import (
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

const emailMovesFile = "email-moves.json"

type emailMoveState struct {
	Aliases map[string]string
	Pending *emailMoveIntent `json:",omitempty"`
}

type emailMoveIntent struct {
	EmailID, Source, Destination string
	SourceValidity, DestValidity uint32
	SourceUID, DestNextUID       imap.UID
}

func (op *operation) updateEmail(id string, raw json.RawMessage) object {
	var patch rawObject
	if !decodeStrict(raw, &patch) || patch == nil {
		return object{"type": "invalidPatch"}
	}
	mailboxChanges, keywords := make(rawObject), make(rawObject)
	for path, value := range patch {
		if path == "mailboxIds" || strings.HasPrefix(path, "mailboxIds/") {
			mailboxChanges[path] = value
		} else {
			keywords[path] = value
		}
	}
	change, valid := keywordPatch(keywords)
	if !valid {
		return object{"type": "invalidPatch"}
	}
	email := op.snapshot.emails[id]
	if email == nil {
		return object{"type": "notFound"}
	}
	mailbox := op.snapshot.mailbox(email.MailboxID)
	if len(mailboxChanges) > 0 {
		target, failure := op.emailMailboxChange(email, mailboxChanges)
		if failure != nil {
			return failure
		}
		if target.ID != email.MailboxID {
			if !target.allowsKeywordChange(nil, keywordChange{values: email.Keywords}) ||
				!target.allowsKeywordChange(email.Keywords, change) {
				return object{"type": "forbidden"}
			}
			if failure := op.moveEmail(email, target); failure != "" {
				return object{"type": failure}
			}
			// MOVE confirms the destination and refreshes the Email locator.
			// A subsequent STORE failure leaves the confirmed move visible.
			email = op.snapshot.emails[id]
			mailbox = target
		}
	}
	if !mailbox.allowsKeywordChange(email.Keywords, change) {
		return object{"type": "forbidden"}
	}
	if failure := op.applyEmailKeywords(email, change); failure != "" {
		return object{"type": failure}
	}
	return nil
}

func (g *Gateway) loadEmailMoves() (emailMoveState, string) {
	if pending := g.unflushedMoves; pending != nil {
		if failure := g.saveEmailMoves(*pending); failure != "" {
			return emailMoveState{}, failure
		}
		g.unflushedMoves = nil
		return *pending, ""
	}
	file, err := os.Open(filepath.Join(g.config.StateDir, emailMovesFile))
	if os.IsNotExist(err) {
		return emailMoveState{Aliases: make(map[string]string)}, ""
	}
	if err != nil {
		return emailMoveState{}, "serverFail"
	}
	defer file.Close()
	data, large, err := take(file, maxHistoryFile)
	var state emailMoveState
	if err != nil || large || json.Unmarshal(data, &state) != nil || state.Aliases == nil {
		return emailMoveState{}, "serverFail"
	}
	return state, ""
}

func (g *Gateway) saveEmailMoves(state emailMoveState) string {
	err := g.ledger.files.replace(g.config.StateDir, emailMovesFile, ".email-moves-*", func(w io.Writer) error {
		return json.NewEncoder(w).Encode(state)
	})
	if err != nil {
		return "serverFail"
	}
	return ""
}

func (state emailMoveState) resolve(locator string) string {
	if id := state.Aliases[locator]; id != "" {
		return id
	}
	return locator
}

func (g *Gateway) reconcileEmailMove(s *snapshot) string {
	intent := s.moves.Pending
	if intent == nil {
		return ""
	}
	source := s.emails[intent.EmailID]
	target := s.mailbox(intent.Destination)
	// A source still at the original locator and an unchanged destination
	// UIDNEXT prove that no COPYUID could have been allocated by the move.
	if source == nil || source.MailboxID != intent.Source || source.Validity != intent.SourceValidity || source.UID != intent.SourceUID ||
		target == nil || target.Validity != intent.DestValidity || target.NextUID == 0 || target.NextUID != intent.DestNextUID {
		return "serverFail"
	}
	s.moves.Pending = nil
	return g.saveEmailMoves(s.moves)
}

func (op *operation) emailMailboxChange(email *emailMeta, patch rawObject) (*box, object) {
	ids := map[string]bool{email.MailboxID: true}
	if raw, ok := patch["mailboxIds"]; ok {
		var replacement map[string]bool
		if len(patch) != 1 || !decodeStrict(raw, &replacement) || replacement == nil {
			return nil, object{"type": "invalidPatch"}
		}
		clear(ids)
		for requested, present := range replacement {
			id := op.resolveID(requested)
			if !present || op.snapshot.mailbox(id) == nil {
				return nil, invalidMailboxProperty("mailboxIds")
			}
			ids[id] = true
		}
	} else {
		seen := make(map[string]bool)
		for path, raw := range patch {
			requested := strings.TrimPrefix(path, "mailboxIds/")
			id := op.resolveID(requested)
			var value *bool
			if id == "" || !jmapID.MatchString(id) || seen[id] || !decodeStrict(raw, &value) || value != nil && !*value {
				return nil, object{"type": "invalidPatch"}
			}
			seen[id] = true
			if value == nil {
				delete(ids, id)
			} else {
				if op.snapshot.mailbox(id) == nil {
					return nil, invalidMailboxProperty("mailboxIds")
				}
				ids[id] = true
			}
		}
	}
	if len(ids) > 1 {
		return nil, object{"type": "tooManyMailboxes"}
	}
	if len(ids) == 0 {
		return nil, invalidMailboxProperty("mailboxIds")
	}
	return op.snapshot.mailbox(sortedKeys(ids)[0]), nil
}

func (op *operation) moveEmail(email *emailMeta, target *box) string {
	if !target.Writable || !op.snapshot.mailbox(email.MailboxID).allowsRemoval() || !supportsNativeUIDMove(op.client.Caps()) {
		return "forbidden"
	}
	if failure := selectEmail(op.client, email, false); failure != "" {
		return failure
	}
	flags, failure := fetchEmailFlags(op.client, email.UID)
	if failure != "" || flagPresent(flags, imap.FlagDeleted) {
		return hiddenEmailFailure(failure)
	}
	status, err := op.client.Status(target.Path, &imap.StatusOptions{UIDValidity: true, UIDNext: true}).Wait()
	if err != nil {
		return emailMutationFailure(err, false)
	}
	if status.UIDValidity != target.Validity || status.UIDNext == 0 {
		return "serverFail"
	}
	state := op.snapshot.moves
	state.Pending = &emailMoveIntent{EmailID: email.ID, Source: email.MailboxID, SourceValidity: email.Validity,
		SourceUID: email.UID, Destination: target.ID, DestValidity: status.UIDValidity, DestNextUID: status.UIDNext}
	if failure := op.g.saveEmailMoves(state); failure != "" {
		return failure
	}
	data, err := op.client.Move(imap.UIDSetNum(email.UID), target.Path).Wait()
	if err != nil {
		var reply *imap.Error
		failure := emailMutationFailure(err, false)
		if errors.As(err, &reply) {
			// A rejected MOVE may have partially completed in IMAP. A fresh
			// scan clears the intent only if both locations prove no change.
			if fresh, refreshFailure := op.g.scan(op.client); refreshFailure == "" {
				op.snapshot = fresh
				return failure
			}
		}
		op.snapshotFailure = failure
		return failure
	}
	destinationUID := movedUID(data, email.UID)
	if destinationUID == 0 || data.UIDValidity == status.UIDValidity && destinationUID < status.UIDNext {
		op.snapshotFailure = "serverFail"
		return op.snapshotFailure
	}
	state.Aliases = maps.Clone(state.Aliases)
	delete(state.Aliases, emailID(email.MailboxID, email.Validity, email.UID))
	state.Aliases[emailID(target.ID, data.UIDValidity, destinationUID)] = email.ID
	state.Pending = nil
	if failure := op.g.saveEmailMoves(state); failure != "" {
		// The acknowledged mapping can be flushed before exposing a new
		// snapshot if storage recovers while this process remains alive.
		op.g.unflushedMoves = &state
		op.snapshotFailure = failure
		return failure
	}
	op.snapshot.moves = state
	// Refresh to confirm the destination and incorporate any UIDVALIDITY or
	// delivery changes detected while the command was in flight.
	fresh, failure := op.g.scan(op.client)
	if failure != "" {
		op.snapshotFailure = failure
		return failure
	}
	op.snapshot = fresh
	if moved := fresh.emails[email.ID]; moved == nil || moved.MailboxID != target.ID {
		return "notFound"
	}
	return ""
}

func supportsNativeUIDMove(caps imap.CapSet) bool {
	// The dependency falls back to COPY, STORE and EXPUNGE without MOVE.
	return caps.Has(imap.CapMove) && supportsUIDExpunge(caps)
}

func movedUID(data *imapclient.MoveData, expected imap.UID) imap.UID {
	if data == nil || data.UIDValidity == 0 {
		return 0
	}
	source, sourceOK := data.SourceUIDs.(imap.UIDSet)
	destination, destOK := data.DestUIDs.(imap.UIDSet)
	if !sourceOK || !destOK || len(source) != 1 || len(destination) != 1 {
		return 0
	}
	if source[0].Start != expected || source[0].Stop != expected || destination[0].Start != destination[0].Stop {
		return 0
	}
	return destination[0].Start
}
