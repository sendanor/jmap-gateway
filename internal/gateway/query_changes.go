package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

type queryDefinition struct {
	Filter          rawObject   `json:"filter"`
	Sort            []querySort `json:"sort"`
	SortAsTree      bool        `json:"sortAsTree"`
	FilterAsTree    bool        `json:"filterAsTree"`
	CollapseThreads bool        `json:"collapseThreads"`
}

type queryResults struct {
	Rows    []queryRow
	Mutable bool
}

type queryRow struct {
	ID       string
	Revision string `json:"revision,omitempty"`
}

type queryObservation struct {
	State string
	Rows  []queryRow
}

const (
	maxQuerySnapshots = 128
	maxQueryRows      = 50000
	queryHistoryFile  = "query-history.json"
)

type queryHistory struct {
	dir          string
	files        atomicFiles
	loaded       bool
	dirty        bool
	observations []queryObservation
}

func (h *queryHistory) load() {
	if h.loaded {
		return
	}
	h.loaded = true
	file, err := os.Open(filepath.Join(h.dir, queryHistoryFile))
	if err != nil {
		return
	}
	defer file.Close()
	data, large, err := take(file, maxHistoryFile)
	if err != nil || large || json.Unmarshal(data, &h.observations) != nil {
		h.observations = nil
	}
}

func (h *queryHistory) find(state string) int {
	h.load()
	return slices.IndexFunc(h.observations, func(entry queryObservation) bool { return entry.State == state })
}

func (h *queryHistory) remember(observation queryObservation) {
	index := h.find(observation.State)
	switch {
	case index < 0:
		h.observations = append(h.observations, observation)
		h.dirty = true
	case index < len(h.observations)-1:
		// Keep actively used query states at the end of the retention window.
		copy(h.observations[index:], h.observations[index+1:])
		h.observations[len(h.observations)-1] = observation
		h.dirty = true
	}
	if !h.dirty {
		return
	}
	h.trim()
	err := h.files.replace(h.dir, queryHistoryFile, ".queries-*", func(w io.Writer) error {
		return json.NewEncoder(w).Encode(h.observations)
	})
	h.dirty = err != nil
}

func (h *queryHistory) trim() {
	count := 0
	for i := len(h.observations) - 1; i >= 0; i-- {
		count += len(h.observations[i].Rows)
		if count > maxQueryRows || len(h.observations)-i > maxQuerySnapshots {
			clear(h.observations[:i+1])
			h.observations = h.observations[i+1:]
			break
		}
	}
}

func (op *operation) executeQuery(kind string, raw rawObject) (object, string) {
	var args queryArgs
	if !decodeArgs(raw, &args) || !validQueryWindow(args) {
		return nil, "invalidArguments"
	}
	query, failure := op.evaluateQuery(kind, args.queryDefinition, raw)
	if failure != "" {
		return nil, failure
	}
	observation := op.queryObservation(kind, args.queryDefinition, query.Rows)
	ids := make([]string, 0, len(query.Rows))
	for _, row := range query.Rows {
		ids = append(ids, row.ID)
	}
	result, failure := op.queryWindow(ids, args, observation.State)
	if failure == "" {
		op.g.queries.remember(observation)
	}
	return result, failure
}

func (op *operation) evaluateQuery(kind string, definition queryDefinition, raw rawObject) (queryResults, string) {
	if kind != "Mailbox" && (raw["sortAsTree"] != nil || raw["filterAsTree"] != nil) {
		return queryResults{}, "invalidArguments"
	}
	if kind != "Email" && raw["collapseThreads"] != nil {
		return queryResults{}, "invalidArguments"
	}
	if kind != "Email" && slices.ContainsFunc(definition.Sort, func(sort querySort) bool { return sort.Keyword != nil }) {
		return queryResults{}, "invalidArguments"
	}
	switch kind {
	case "Mailbox":
		return op.evaluateMailboxes(definition)
	case "Email":
		return op.evaluateEmails(definition)
	default:
		return op.evaluateSubmissions(definition)
	}
}

func (op *operation) queryObservation(kind string, definition queryDefinition, rows []queryRow) queryObservation {
	// Normalize JSON object members and bind creation references to the IDs
	// they represent. Paging arguments never affect the query identity.
	filterJSON, _ := json.Marshal(definition.Filter)
	decoder := json.NewDecoder(bytes.NewReader(filterJSON))
	decoder.UseNumber()
	var filter map[string]any
	_ = decoder.Decode(&filter)
	if len(filter) == 0 {
		filter = nil
	}
	op.bindQueryIDs(filter)
	order := make([][]any, 0, len(definition.Sort))
	for _, comparator := range definition.Sort {
		fields := []any{comparator.Property, comparator.ascending(), comparator.Collation}
		if comparator.Keyword != nil {
			fields = append(fields, strings.ToLower(*comparator.Keyword))
		}
		order = append(order, fields)
	}
	scope := []any{kind, filter, order, definition.SortAsTree, definition.FilterAsTree}
	if definition.CollapseThreads {
		scope = append(scope, true)
	}
	key := op.g.signCursor(digest(scope))
	return queryObservation{State: key + "." + digest(rows), Rows: rows}
}

func (op *operation) bindQueryIDs(filter map[string]any) {
	for key, value := range filter {
		switch key {
		case "conditions":
			for _, child := range value.([]any) {
				op.bindQueryIDs(child.(map[string]any))
			}
		case "parentId", "inMailbox":
			if id, ok := value.(string); ok {
				filter[key] = op.resolveID(id)
			}
		case "identityIds", "emailIds", "threadIds", "inMailboxOtherThan":
			for i, id := range value.([]any) {
				value.([]any)[i] = op.resolveID(id.(string))
			}
		}
	}
}

func (op *operation) queryChanges(kind string, raw rawObject) (object, string) {
	var args struct {
		accountArgs
		queryDefinition
		SinceQueryState string `json:"sinceQueryState"`
		MaxChanges      *int64 `json:"maxChanges"`
		UpToID          string `json:"upToId"`
		CalculateTotal  bool   `json:"calculateTotal"`
	}
	if !decodeArgs(raw, &args) || args.SinceQueryState == "" ||
		args.MaxChanges != nil && (*args.MaxChanges < 0 || *args.MaxChanges > maxJMAPInt) ||
		args.UpToID != "" && !jmapID.MatchString(op.resolveID(args.UpToID)) {
		return nil, "invalidArguments"
	}
	query, failure := op.evaluateQuery(kind, args.queryDefinition, raw)
	if failure != "" {
		return nil, failure
	}
	now := op.queryObservation(kind, args.queryDefinition, query.Rows)
	cache := &op.g.queries
	index := cache.find(args.SinceQueryState)
	if index < 0 || len(args.SinceQueryState) != len(now.State) || args.SinceQueryState[:43] != now.State[:43] {
		return nil, "cannotCalculateChanges"
	}
	before := cache.observations[index]
	upToID := ""
	if !query.Mutable {
		upToID = op.resolveID(args.UpToID)
	}
	removed, added := queryDifference(before.Rows, now.Rows, upToID)
	if args.MaxChanges != nil && int64(len(removed)+len(added)) > *args.MaxChanges {
		return nil, "tooManyChanges"
	}
	cache.remember(now)
	result := object{"oldQueryState": args.SinceQueryState, "newQueryState": now.State, "removed": removed, "added": added}
	if args.CalculateTotal {
		result["total"] = len(now.Rows)
	}
	return result, ""
}

type queryAddition struct {
	ID    string `json:"id"`
	Index int    `json:"index"`
}

func queryDifference(before, now []queryRow, upToID string) ([]string, []queryAddition) {
	if upToID != "" {
		oldAnchor := slices.IndexFunc(before, func(row queryRow) bool { return row.ID == upToID })
		newAnchor := slices.IndexFunc(now, func(row queryRow) bool { return row.ID == upToID })
		if oldAnchor >= 0 && newAnchor >= 0 && !rowsCrossAnchor(before, now, oldAnchor, newAnchor) {
			before, now = before[:oldAnchor+1], now[:newAnchor+1]
		}
	}
	keep := stableQueryRows(before, now)
	removed, added := []string{}, []queryAddition{}
	for _, row := range before {
		if !keep[row.ID] {
			removed = append(removed, row.ID)
		}
	}
	for index, row := range now {
		if !keep[row.ID] {
			added = append(added, queryAddition{ID: row.ID, Index: index})
		}
	}
	return removed, added
}

// A persisted query may have used an older ordering. Include the whole
// delta if a surviving row crossed the anchor’s boundary.
func rowsCrossAnchor(before, now []queryRow, oldAnchor, newAnchor int) bool {
	positions := make(map[string]int, len(before))
	for i, row := range before {
		positions[row.ID] = i
	}
	for i, row := range now {
		if previous, found := positions[row.ID]; found && (previous <= oldAnchor) != (i <= newAnchor) {
			return true
		}
	}
	return false
}

// Keep a longest order-preserving subsequence of unchanged records. All other
// rows require removal, insertion or both, including mutable rows whose
// filter or sort inputs changed even when their displayed index did not.
func stableQueryRows(before, now []queryRow) map[string]bool {
	indices := make(map[string]int, len(now))
	for i, row := range now {
		indices[row.ID] = i
	}
	var tails []int
	predecessor := make(map[int]int, len(before))
	for _, prior := range before {
		index, found := indices[prior.ID]
		if !found || prior.Revision != now[index].Revision {
			continue
		}
		at := sort.SearchInts(tails, index)
		if at > 0 {
			predecessor[index] = tails[at-1]
		}
		if at == len(tails) {
			tails = append(tails, index)
		} else {
			tails[at] = index
		}
	}
	keep := make(map[string]bool, len(tails))
	if len(tails) == 0 {
		return keep
	}
	index, ok := tails[len(tails)-1], true
	for ok {
		keep[now[index].ID] = true
		index, ok = predecessor[index]
	}
	return keep
}
