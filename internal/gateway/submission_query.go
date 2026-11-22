package gateway

import (
	"slices"
	"strings"
	"time"
)

func (op *operation) evaluateSubmissions(args queryDefinition) (queryResults, string) {
	comparators := make([]func(string, string) int, len(args.Sort))
	for index, comparator := range args.Sort {
		switch comparator.Property {
		case "emailId", "threadId":
			if !supportedQueryCollation(comparator.Collation) {
				return queryResults{}, "unsupportedSort"
			}
			comparators[index] = queryStringComparator(comparator.Collation)
		case "sentAt", "sendAt":
		default:
			return queryResults{}, "unsupportedSort"
		}
	}
	match, failure := compileFilter(args.Filter, op.submissionCondition, 0)
	if failure != "" {
		return queryResults{}, failure
	}
	records := op.submissions()
	ordered := make([]submissionRecord, 0, len(records))
	for _, record := range records {
		if match(record) {
			ordered = append(ordered, record)
		}
	}
	slices.SortFunc(ordered, func(a, b submissionRecord) int {
		for index, comparator := range args.Sort {
			comparison := a.SendAt.Truncate(time.Second).Compare(b.SendAt.Truncate(time.Second))
			switch comparator.Property {
			case "emailId":
				comparison = comparators[index](a.EmailID, b.EmailID)
			case "threadId":
				comparison = comparators[index](threadID(a.EmailID, a.ThreadID), threadID(b.EmailID, b.ThreadID))
			}
			if comparison != 0 {
				if comparator.ascending() {
					return comparison
				}
				return -comparison
			}
		}
		return strings.Compare(a.ID, b.ID)
	})
	rows := make([]queryRow, 0, len(ordered))
	for _, record := range ordered {
		rows = append(rows, queryRow{ID: record.ID})
	}
	return queryResults{Rows: rows, Mutable: filterHasProperty(args.Filter, "undoStatus")}, ""
}

func (op *operation) submissionCondition(filter rawObject) (func(submissionRecord) bool, string) {
	tests := make([]func(submissionRecord) bool, 0, len(filter))
	for key, raw := range filter {
		switch key {
		case "identityIds", "emailIds", "threadIds":
			var ids []string
			if !decodeStrict(raw, &ids) || ids == nil {
				return nil, "invalidArguments"
			}
			allowed := make(map[string]bool, len(ids))
			for _, id := range ids {
				resolved := op.resolveID(id)
				if !jmapID.MatchString(resolved) {
					return nil, "invalidArguments"
				}
				allowed[resolved] = true
			}
			tests = append(tests, func(entry submissionRecord) bool {
				switch key {
				case "identityIds":
					return allowed[entry.IdentityID]
				case "emailIds":
					return allowed[entry.EmailID]
				default:
					return allowed[threadID(entry.EmailID, entry.ThreadID)]
				}
			})
		case "undoStatus":
			var status string
			if !decodeStrict(raw, &status) || status == "" {
				return nil, "invalidArguments"
			}
			tests = append(tests, func(submissionRecord) bool { return status == "final" })
		case "before", "after":
			var date string
			if !decodeStrict(raw, &date) || !strings.HasSuffix(date, "Z") {
				return nil, "invalidArguments"
			}
			instant, err := time.Parse(time.RFC3339, date)
			if err != nil {
				return nil, "invalidArguments"
			}
			tests = append(tests, func(entry submissionRecord) bool {
				// The protocol exposes sendAt at second precision.
				before := entry.SendAt.Truncate(time.Second).Before(instant)
				return (key == "before") == before
			})
		default:
			return nil, "unsupportedFilter"
		}
	}
	return func(entry submissionRecord) bool { return queryMatches("AND", tests, entry) }, ""
}

func filterHasProperty(filter rawObject, property string) bool {
	if filter[property] != nil {
		return true
	}
	var children []rawObject
	_ = decodeStrict(filter["conditions"], &children)
	return slices.ContainsFunc(children, func(child rawObject) bool { return filterHasProperty(child, property) })
}
