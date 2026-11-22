package gateway

import (
	"cmp"
	"encoding/json"
	"slices"
	"strings"
)

const maxJMAPInt = (1 << 53) - 1

func validQueryWindow(args queryArgs) bool {
	return (args.Limit == nil || *args.Limit >= 0 && *args.Limit <= maxJMAPInt) &&
		args.Position >= -maxJMAPInt && args.Position <= maxJMAPInt &&
		args.AnchorOffset >= -maxJMAPInt && args.AnchorOffset <= maxJMAPInt
}

func (s querySort) ascending() bool { return s.IsAscending == nil || *s.IsAscending }

func (op *operation) queryMailboxes(raw rawObject) (object, string) {
	return op.executeQuery("Mailbox", raw)
}

func (op *operation) evaluateMailboxes(args queryDefinition) (queryResults, string) {
	comparators := make([]func(string, string) int, len(args.Sort))
	for index, order := range args.Sort {
		switch order.Property {
		case "name":
			if !supportedQueryCollation(order.Collation) {
				return queryResults{}, "unsupportedSort"
			}
			comparators[index] = queryStringComparator(order.Collation)
		case "sortOrder":
			// The collation option applies to strings only.
		default:
			return queryResults{}, "unsupportedSort"
		}
	}
	match, failure := compileFilter(args.Filter, op.mailboxCondition, 0)
	if failure != "" {
		return queryResults{}, failure
	}
	if failure := op.loadMail(); failure != "" {
		return queryResults{}, failure
	}

	ordered := slices.Clone(op.snapshot.boxes)
	slices.SortFunc(ordered, func(a, b *box) int {
		for index, order := range args.Sort {
			result := cmp.Compare(a.SortOrder, b.SortOrder)
			if order.Property == "name" {
				result = comparators[index](a.Name, b.Name)
			}
			if result != 0 {
				if order.ascending() {
					return result
				}
				return -result
			}
		}
		return strings.Compare(a.ID, b.ID)
	})
	if args.SortAsTree {
		ordered = mailboxTreeOrder(ordered)
	}
	matches := make(map[string]bool, len(ordered))
	parents := make(map[string]string, len(ordered))
	for _, mailbox := range ordered {
		matches[mailbox.ID] = match(mailbox)
		parents[mailbox.ID] = mailbox.ParentID
	}
	mutable := len(args.Filter) > 0 || args.SortAsTree || len(args.Sort) > 0
	rows := make([]queryRow, 0, len(ordered))
	for _, mailbox := range ordered {
		if !matches[mailbox.ID] {
			continue
		}
		if args.FilterAsTree && !matchingAncestors(mailbox.ParentID, parents, matches) {
			continue
		}
		row := queryRow{ID: mailbox.ID}
		if mutable {
			row.Revision = digest(struct {
				Name, ParentID, Role string
				Subscribed           bool
				SortOrder            uint32 `json:",omitempty"`
			}{mailbox.Name, mailbox.ParentID, mailbox.Role, mailbox.Subscribed, mailbox.SortOrder})
		}
		rows = append(rows, row)
	}
	return queryResults{Rows: rows, Mutable: mutable}, ""
}

func (op *operation) mailboxCondition(filter rawObject) (func(*box) bool, string) {
	tests := make([]func(*box) bool, 0, len(filter))
	for key, raw := range filter {
		switch key {
		case "parentId", "role":
			var value *string
			if !decodeStrict(raw, &value) || value != nil && *value == "" {
				return nil, "invalidArguments"
			}
			expected := ""
			if value != nil {
				expected = *value
				if key == "parentId" {
					expected = op.resolveID(expected)
					if expected == "" {
						return nil, "invalidArguments"
					}
				}
			}
			tests = append(tests, func(box *box) bool {
				if key == "role" {
					return box.Role == expected
				}
				return box.ParentID == expected
			})
		case "name":
			var value *string
			if !decodeStrict(raw, &value) || value == nil {
				return nil, "invalidArguments"
			}
			folded := strings.ToLower(*value)
			tests = append(tests, func(box *box) bool {
				return strings.Contains(strings.ToLower(box.Name), folded)
			})
		case "hasAnyRole", "isSubscribed":
			var value *bool
			if !decodeStrict(raw, &value) || value == nil {
				return nil, "invalidArguments"
			}
			tests = append(tests, func(box *box) bool {
				if key == "hasAnyRole" {
					return (box.Role != "") == *value
				}
				return box.Subscribed == *value
			})
		default:
			return nil, "unsupportedFilter"
		}
	}
	return func(mailbox *box) bool { return queryMatches("AND", tests, mailbox) }, ""
}

func compileFilter[T any](filter rawObject, leaf func(rawObject) (func(T) bool, string), depth int) (func(T) bool, string) {
	if depth > 32 {
		return nil, "unsupportedFilter"
	}
	if filter["operator"] == nil && filter["conditions"] == nil {
		return leaf(filter)
	}
	var operator string
	var conditions []rawObject
	if len(filter) != 2 || json.Unmarshal(filter["operator"], &operator) != nil ||
		operator != "AND" && operator != "OR" && operator != "NOT" ||
		json.Unmarshal(filter["conditions"], &conditions) != nil || conditions == nil {
		return nil, "invalidArguments"
	}
	tests := make([]func(T) bool, 0, len(conditions))
	for _, condition := range conditions {
		if condition == nil {
			return nil, "invalidArguments"
		}
		test, failure := compileFilter(condition, leaf, depth+1)
		if failure != "" {
			return nil, failure
		}
		tests = append(tests, test)
	}
	return func(value T) bool { return queryMatches(operator, tests, value) }, ""
}

func queryMatches[T any](operator string, tests []func(T) bool, value T) bool {
	for _, match := range tests {
		matches := match(value)
		if !matches && operator == "AND" {
			return false
		}
		if matches && operator != "AND" {
			return operator == "OR"
		}
	}
	return operator != "OR"
}

func mailboxTreeOrder(ordered []*box) []*box {
	byParent := make(map[string][]*box, len(ordered))
	for _, mailbox := range ordered {
		byParent[mailbox.ParentID] = append(byParent[mailbox.ParentID], mailbox)
	}
	result := make([]*box, 0, len(ordered))
	var visit func(string)
	visit = func(parent string) {
		for _, child := range byParent[parent] {
			result = append(result, child)
			visit(child.ID)
		}
	}
	visit("")
	return result
}

func matchingAncestors(parent string, parents map[string]string, matches map[string]bool) bool {
	for parent != "" {
		if !matches[parent] {
			return false
		}
		parent = parents[parent]
	}
	return true
}
