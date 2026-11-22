package gateway

import (
	"cmp"
	"slices"
	"strings"
	"time"
)

var emailQuerySortOptions = []string{
	"receivedAt", "size", "from", "to", "subject", "sentAt",
	"hasKeyword", "allInThreadHaveKeyword", "someInThreadHaveKeyword",
}

type threadKeywordCounts struct {
	total    int
	keywords map[string]int
}

type emailQuery struct {
	op             *operation
	trackThreads   bool
	threads        map[string]*threadKeywordCounts
	keywordValues  []func(*emailMeta) bool
	needsMIME      bool
	content        emailSearch
	headerOrder    map[string]emailSortHeaders
	mailboxFilters []string
}

func (op *operation) evaluateEmails(args queryDefinition) (queryResults, string) {
	query := emailQuery{op: op}
	comparators, failure := query.comparators(args.Sort)
	if failure != "" {
		return queryResults{}, failure
	}
	match, failure := compileFilter(args.Filter, query.condition, 0)
	if failure != "" {
		return queryResults{}, failure
	}
	if failure := op.loadMail(); failure != "" {
		return queryResults{}, failure
	}
	if !query.allowsMailboxFilters() {
		return queryResults{}, "forbidden"
	}
	if query.trackThreads {
		query.collectThreadKeywords(op.snapshot.emails)
	}
	messages := make([]*emailMeta, 0, len(op.snapshot.emails))
	for _, email := range op.snapshot.emails {
		query.content = emailSearch{op: op, needsMIME: query.needsMIME}
		matched := match(email)
		if matched && query.headerOrder != nil {
			// A metadata branch may have satisfied the filter without reading
			// the message. The sort keys only need its headers in that case.
			query.content.needsMIME = false
			if query.content.load(email) {
				query.headerOrder[email.ID] = sortHeaders(query.content.header)
			}
		}
		if failure := query.content.failure; failure != "" {
			if failure == "notFound" {
				// A vanished IMAP candidate would make the result incomplete.
				return queryResults{}, "serverUnavailable"
			}
			return queryResults{}, failure
		}
		if matched {
			messages = append(messages, email)
		}
	}
	// Preserve received-date ordering for ties. The final key must remain
	// stable when an IMAP MOVE changes both the mailbox and UID.
	direction := -1
	if len(args.Sort) > 0 && args.Sort[0].Property == "receivedAt" && args.Sort[0].ascending() {
		direction = 1
	}
	slices.SortFunc(messages, func(a, b *emailMeta) int {
		for _, compare := range comparators {
			if order := compare(a, b); order != 0 {
				return order
			}
		}
		if order := a.Received.Compare(b.Received); order != 0 {
			return direction * order
		}
		return strings.Compare(a.ID, b.ID)
	})
	rows := make([]queryRow, 0, len(messages))
	seenThreads := make(map[string]bool)
	mailboxFilter := filterHasProperty(args.Filter, "inMailbox") || filterHasProperty(args.Filter, "inMailboxOtherThan")
	for _, email := range messages {
		if args.CollapseThreads {
			id := threadID(email.ID, email.ThreadID)
			if seenThreads[id] {
				continue
			}
			seenThreads[id] = true
		}
		row := queryRow{ID: email.ID}
		if len(query.keywordValues) > 0 {
			// The same ID may need removal and reinsertion even if its index
			// stayed fixed. Record only relevant booleans, never raw flags.
			values := make([]byte, len(query.keywordValues))
			for index, value := range query.keywordValues {
				values[index] = '0' + byte(queryBool(value(email)))
			}
			row.Revision = digest(string(values))
		}
		if mailboxFilter {
			row.Revision = digest([]string{row.Revision, email.MailboxID})
		}
		rows = append(rows, row)
	}
	mutable := len(query.keywordValues) > 0 || mailboxFilter
	return queryResults{Rows: rows, Mutable: mutable}, ""
}

func (q *emailQuery) comparators(sorts []querySort) ([]func(*emailMeta, *emailMeta) int, string) {
	comparators := make([]func(*emailMeta, *emailMeta) int, 0, len(sorts))
	for _, sort := range sorts {
		var compare func(*emailMeta, *emailMeta) int
		keywordSort := false
		switch sort.Property {
		case "receivedAt":
			compare = func(a, b *emailMeta) int { return a.Received.Compare(b.Received) }
		case "size":
			compare = func(a, b *emailMeta) int { return cmp.Compare(a.Size, b.Size) }
		case "from", "to", "subject", "sentAt":
			if sort.Property != "sentAt" && !supportedQueryCollation(sort.Collation) {
				return nil, "unsupportedSort"
			}
			if q.headerOrder == nil {
				q.headerOrder = make(map[string]emailSortHeaders)
			}
			compareText := queryStringComparator(sort.Collation)
			compare = func(a, b *emailMeta) int {
				return compareSortHeaders(q.headerOrder[a.ID], q.headerOrder[b.ID], sort.Property, compareText)
			}
		case "hasKeyword", "allInThreadHaveKeyword", "someInThreadHaveKeyword":
			keywordSort = true
			if sort.Keyword == nil || !validKeyword(*sort.Keyword) {
				return nil, "invalidArguments"
			}
			value := q.keywordValue(sort.Property, *sort.Keyword)
			compare = func(a, b *emailMeta) int { return cmp.Compare(queryBool(value(a)), queryBool(value(b))) }
		default:
			return nil, "unsupportedSort"
		}
		if sort.Keyword != nil && !keywordSort {
			return nil, "invalidArguments"
		}
		comparators = append(comparators, func(a, b *emailMeta) int {
			if sort.ascending() {
				return compare(a, b)
			}
			return -compare(a, b)
		})
	}
	return comparators, ""
}

func (q *emailQuery) allowsMailboxFilters() bool {
	for _, id := range q.mailboxFilters {
		if !q.op.snapshot.mailbox(id).mayReadItems() {
			return false
		}
	}
	return true
}

func (q *emailQuery) condition(filter rawObject) (func(*emailMeta) bool, string) {
	tests := make([]func(*emailMeta) bool, 0, len(filter))
	var contentTests []func(*emailMeta) bool
	for _, property := range sortedKeys(filter) {
		raw := filter[property]
		var match func(*emailMeta) bool
		switch property {
		case "inMailbox":
			var id string
			if !decodeStrict(raw, &id) || !jmapID.MatchString(q.op.resolveID(id)) {
				return nil, "invalidArguments"
			}
			id = q.op.resolveID(id)
			q.mailboxFilters = append(q.mailboxFilters, id)
			match = func(email *emailMeta) bool { return email.MailboxID == id }
		case "inMailboxOtherThan":
			var ids []string
			if !decodeStrict(raw, &ids) || ids == nil {
				return nil, "invalidArguments"
			}
			excluded := make(map[string]bool, len(ids))
			for _, id := range ids {
				id = q.op.resolveID(id)
				if !jmapID.MatchString(id) {
					return nil, "invalidArguments"
				}
				q.mailboxFilters = append(q.mailboxFilters, id)
				excluded[id] = true
			}
			match = func(email *emailMeta) bool { return !excluded[email.MailboxID] }
		case "before", "after":
			var value string
			if !decodeStrict(raw, &value) || !strings.HasSuffix(value, "Z") {
				return nil, "invalidArguments"
			}
			date, err := time.Parse(time.RFC3339, value)
			if err != nil {
				return nil, "invalidArguments"
			}
			match = func(email *emailMeta) bool { return (property == "before") == email.Received.Before(date) }
		case "minSize", "maxSize":
			var value *int64
			if !decodeStrict(raw, &value) || value == nil || *value < 0 || *value > maxJMAPInt {
				return nil, "invalidArguments"
			}
			match = func(email *emailMeta) bool { return (property == "maxSize") == (email.Size < *value) }
		case "hasKeyword", "notKeyword", "allInThreadHaveKeyword", "someInThreadHaveKeyword", "noneInThreadHaveKeyword":
			var value string
			if !decodeStrict(raw, &value) || !validKeyword(value) {
				return nil, "invalidArguments"
			}
			match = q.keywordValue(property, value)
		default:
			condition, failure := q.contentCondition(property, raw)
			if failure != "" {
				return nil, failure
			}
			contentTests = append(contentTests, condition)
			continue
		}
		tests = append(tests, match)
	}
	tests = append(tests, contentTests...)
	return func(email *emailMeta) bool { return queryMatches("AND", tests, email) }, ""
}

func (q *emailQuery) collectThreadKeywords(emails map[string]*emailMeta) {
	q.threads = make(map[string]*threadKeywordCounts)
	for _, email := range emails {
		id := threadID(email.ID, email.ThreadID)
		counts := q.threads[id]
		if counts == nil {
			counts = &threadKeywordCounts{keywords: make(map[string]int)}
			q.threads[id] = counts
		}
		counts.total++
		for keyword, enabled := range email.Keywords {
			if enabled {
				counts.keywords[keyword]++
			}
		}
	}
}

func (q *emailQuery) keywordValue(property, keyword string) func(*emailMeta) bool {
	keyword = strings.ToLower(keyword)
	if property != "hasKeyword" && property != "notKeyword" {
		q.trackThreads = true
	}
	value := func(email *emailMeta) bool {
		switch property {
		case "hasKeyword":
			return email.Keywords[keyword]
		case "notKeyword":
			return !email.Keywords[keyword]
		}
		counts := q.threads[threadID(email.ID, email.ThreadID)]
		present := counts.keywords[keyword]
		switch property {
		case "allInThreadHaveKeyword":
			return present == counts.total
		case "someInThreadHaveKeyword":
			return present > 0
		default:
			return present == 0
		}
	}
	q.keywordValues = append(q.keywordValues, value)
	return value
}

func queryBool(value bool) int {
	if value {
		return 1
	}
	return 0
}
