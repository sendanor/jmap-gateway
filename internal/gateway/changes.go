package gateway

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strings"
)

const (
	maxHistorySteps   = 1024
	maxHistoryRecords = 50000
	maxHistoryFile    = 16 << 20
	maxChangePage     = 512
)

// Each track keeps its current record fingerprints and only the data required
// to undo retained transitions. IMAP messages, headers and addresses are absent.
type changeHistory struct {
	dir       string
	files     atomicFiles
	tracks    map[string]*changeTrack
	cursorKey [32]byte
}

func openChangeHistory(dir string, files atomicFiles) (changeHistory, error) {
	history := changeHistory{dir: dir, files: files, tracks: make(map[string]*changeTrack)}
	path := filepath.Join(dir, "changes.key")
	key, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		_, _ = rand.Read(history.cursorKey[:])
		if err := files.replace(dir, "changes.key", ".changes-key-*", func(w io.Writer) error {
			_, err := w.Write(history.cursorKey[:])
			return err
		}); err != nil {
			return history, errors.New("cannot create synchronization key")
		}
	case err != nil || len(key) != len(history.cursorKey):
		return history, errors.New("cannot read synchronization key")
	default:
		copy(history.cursorKey[:], key)
	}
	return history, nil
}

type changeTrack struct {
	State       string
	Fingerprint string
	Records     map[string]recordStamp
	Past        []reverseStep
	dirty       bool
}

type recordStamp struct {
	Hash          string `json:"hash,omitempty"`
	Total         int    `json:"total,omitempty"`
	Unread        int    `json:"unread,omitempty"`
	TotalThreads  int    `json:"totalThreads,omitempty"`
	UnreadThreads int    `json:"unreadThreads,omitempty"`
}

type reverseStep struct {
	State    string
	Previous map[string]recordStamp
}

func (h *changeHistory) track(kind string) *changeTrack {
	if track := h.tracks[kind]; track != nil {
		return track
	}
	track := new(changeTrack)
	file, err := os.Open(filepath.Join(h.dir, "changes-"+kind+".json"))
	if err == nil {
		defer file.Close()
		data, large, err := take(file, maxHistoryFile)
		if err != nil || large || json.Unmarshal(data, track) != nil || track.Records == nil || track.State == "" || track.Fingerprint == "" {
			track = new(changeTrack)
		}
	}
	h.tracks[kind] = track
	return track
}

func (h *changeHistory) observe(kind, fingerprint string, stamps func() map[string]recordStamp) *changeTrack {
	track := h.track(kind)
	if track.Fingerprint != fingerprint {
		current := stamps()
		if track.State != "" {
			before := make(map[string]recordStamp)
			for id, previous := range track.Records {
				if current[id] != previous {
					before[id] = previous
				}
			}
			for id := range current {
				if _, existed := track.Records[id]; !existed {
					before[id] = recordStamp{}
				}
			}
			track.Past = append(track.Past, reverseStep{track.State, before})
			track.trim()
			track.State = digest([]string{kind, track.State, fingerprint})
		} else {
			track.State = fingerprint
		}
		track.Fingerprint, track.Records = fingerprint, current
		track.dirty = true
	}
	if track.dirty {
		// Failure to cache an observation must not hide an IMAP mutation or an
		// accepted SMTP submission. The next observation retries the save.
		err := h.files.replace(h.dir, "changes-"+kind+".json", ".changes-*", func(w io.Writer) error {
			return json.NewEncoder(w).Encode(track)
		})
		track.dirty = err != nil
	}
	return track
}

func (t *changeTrack) trim() {
	count := 0
	for i := len(t.Past) - 1; i >= 0; i-- {
		count += len(t.Past[i].Previous)
		if count > maxHistoryRecords || len(t.Past)-i > maxHistorySteps {
			clear(t.Past[:i+1])
			t.Past = t.Past[i+1:]
			break
		}
	}
}

func (t *changeTrack) at(state string) (map[string]recordStamp, int, bool) {
	if state == t.State {
		return t.Records, len(t.Past), true
	}
	for index := len(t.Past) - 1; index >= 0; index-- {
		if step := t.Past[index]; step.State == state {
			records := maps.Clone(t.Records)
			for i := len(t.Past) - 1; i >= index; i-- {
				for id, previous := range t.Past[i].Previous {
					if previous == (recordStamp{}) {
						delete(records, id)
					} else {
						records[id] = previous
					}
				}
			}
			return records, index, true
		}
	}
	return nil, 0, false
}

func (op *operation) state(kind string) string {
	var state string
	var stamps func() map[string]recordStamp
	switch kind {
	case "Mailbox":
		state = op.snapshot.state(kind)
		stamps = func() map[string]recordStamp {
			records := make(map[string]recordStamp, len(op.snapshot.boxes))
			for _, mailbox := range op.snapshot.boxes {
				base := *mailbox
				base.Total, base.Unread, base.TotalThreads, base.UnreadThreads = 0, 0, 0, 0
				records[base.ID] = recordStamp{Hash: digest(base), Total: mailbox.Total, Unread: mailbox.Unread,
					TotalThreads: mailbox.TotalThreads, UnreadThreads: mailbox.UnreadThreads}
			}
			return records
		}
	case "Email":
		state = op.snapshot.state(kind)
		stamps = func() map[string]recordStamp {
			return stampRecords(op.snapshot.emails)
		}
	case "Thread":
		threads := op.snapshot.threads()
		state = digest(threads)
		stamps = func() map[string]recordStamp { return stampRecords(threads) }
	case "Calendar":
		state = digest(op.calendars)
		stamps = func() map[string]recordStamp { return stampRecords(op.calendars) }
	case "Identity":
		identities := op.g.identityRecords()
		state = digest(identities)
		stamps = func() map[string]recordStamp { return stampRecords(identities) }
	default:
		submissions := op.submissions()
		state = digest(submissions)
		stamps = func() map[string]recordStamp {
			return stampRecords(submissions)
		}
	}
	return op.g.history.observe(kind, state, stamps).State
}

func stampRecords[T any](records map[string]T) map[string]recordStamp {
	result := make(map[string]recordStamp, len(records))
	for id, record := range records {
		result[id] = recordStamp{Hash: digest(record)}
	}
	return result
}

type changeCursor struct {
	Kind    string
	From    string
	Through string
	After   string
}

func (g *Gateway) signCursor(payload string) string {
	mac := hmac.New(sha256.New, g.history.cursorKey[:])
	mac.Write([]byte(g.config.AccountID))
	mac.Write([]byte{0})
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (g *Gateway) encodeCursor(cursor changeCursor) string {
	data, _ := json.Marshal(cursor)
	payload := base64.RawURLEncoding.EncodeToString(data)
	return "page." + payload + "." + g.signCursor(payload)
}

func (g *Gateway) decodeCursor(token, kind string) (changeCursor, bool) {
	var cursor changeCursor
	payload, signature, ok := strings.Cut(strings.TrimPrefix(token, "page."), ".")
	if !ok || len(payload) > 1024 || !hmac.Equal([]byte(signature), []byte(g.signCursor(payload))) {
		return cursor, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	valid := err == nil && decodeStrict(raw, &cursor) && cursor.Kind == kind && cursor.After != ""
	return cursor, valid
}

func (op *operation) changes(kind string, raw rawObject) (object, string) {
	var args struct {
		accountArgs
		SinceState string `json:"sinceState"`
		MaxChanges *int64 `json:"maxChanges"`
	}
	if !decodeArgs(raw, &args) || args.SinceState == "" ||
		args.MaxChanges != nil && (*args.MaxChanges < 1 || *args.MaxChanges > 1<<53-1) {
		return nil, "invalidArguments"
	}
	if kind == "Email" || kind == "Mailbox" || kind == "Thread" {
		if failure := op.loadMail(); failure != "" {
			return nil, failure
		}
	}
	if kind == "Calendar" {
		if failure := op.loadCalendars(); failure != "" {
			return nil, failure
		}
	}
	latest := op.state(kind)
	cursor := changeCursor{Kind: kind, From: args.SinceState, Through: latest}
	if strings.HasPrefix(args.SinceState, "page.") {
		var ok bool
		cursor, ok = op.g.decodeCursor(args.SinceState, kind)
		if !ok {
			return nil, "cannotCalculateChanges"
		}
	}
	track := op.g.history.track(kind)
	from, first, foundFrom := track.at(cursor.From)
	to, last, foundTo := track.at(cursor.Through)
	if !foundFrom || !foundTo || first > last {
		return nil, "cannotCalculateChanges"
	}
	limit := maxChangePage
	if args.MaxChanges != nil {
		limit = int(min(int64(limit), *args.MaxChanges))
	}
	ids := changedIDs(from, to, track.Past[first:last], cursor.After)
	newState := cursor.Through
	if len(ids) > limit {
		ids = ids[:limit]
		cursor.After = ids[len(ids)-1]
		newState = op.g.encodeCursor(cursor)
	}
	created, updated, destroyed := []string{}, []string{}, []string{}
	countsOnly := true
	var countChanged [4]bool
	for _, id := range ids {
		before, existed := from[id]
		now, exists := to[id]
		switch {
		case !existed:
			created = append(created, id)
			countsOnly = false
		case !exists:
			destroyed = append(destroyed, id)
			countsOnly = false
		default:
			updated = append(updated, id)
			countsOnly = countsOnly && before != now && before.Hash == now.Hash
			countChanged[0] = countChanged[0] || before.Total != now.Total
			countChanged[1] = countChanged[1] || before.Unread != now.Unread
			countChanged[2] = countChanged[2] || before.TotalThreads != now.TotalThreads
			countChanged[3] = countChanged[3] || before.UnreadThreads != now.UnreadThreads
		}
	}
	result := object{
		"oldState": args.SinceState, "newState": newState, "hasMoreChanges": newState != latest,
		"created": created, "updated": updated, "destroyed": destroyed,
	}
	if kind == "Mailbox" {
		var properties []string
		if countsOnly {
			for index, property := range [...]string{"totalEmails", "unreadEmails", "totalThreads", "unreadThreads"} {
				if countChanged[index] {
					properties = append(properties, property)
				}
			}
		}
		result["updatedProperties"] = properties
	}
	return result, ""
}

func changedIDs(from, to map[string]recordStamp, steps []reverseStep, after string) []string {
	ids := make(map[string]struct{})
	for _, step := range steps {
		for id := range step.Previous {
			if id > after && (from[id] != (recordStamp{}) || to[id] != (recordStamp{})) {
				ids[id] = struct{}{}
			}
		}
	}
	return sortedKeys(ids)
}
