package gateway

import (
	"html"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxSnippetBytes = 255

func (op *operation) searchSnippets(raw rawObject) (object, string) {
	var args struct {
		accountArgs
		Filter rawObject `json:"filter"`
		IDs    []string  `json:"emailIds"`
	}
	if !decodeArgs(raw, &args) || args.IDs == nil {
		return nil, "invalidArguments"
	}
	if len(args.IDs) > maxGet {
		return nil, "requestTooLarge"
	}
	for _, id := range args.IDs {
		if !jmapID.MatchString(strings.TrimPrefix(id, "#")) {
			return nil, "invalidArguments"
		}
	}
	query := emailQuery{op: op}
	if _, failure := compileFilter(args.Filter, query.condition, 0); failure != "" {
		return nil, failure
	}
	list := make([]object, 0, len(args.IDs))
	var missing []string
	if len(args.IDs) > 0 {
		if failure := op.loadMail(); failure != "" {
			return nil, failure
		}
		if !query.allowsMailboxFilters() {
			return nil, "forbidden"
		}
		var terms snippetTerms
		terms.collect(args.Filter, true)
		seen := make(map[string]bool, len(args.IDs))
		for _, requested := range args.IDs {
			id := op.resolveID(requested)
			email := op.snapshot.emails[id]
			if email == nil {
				missing = append(missing, requested)
				continue
			}
			if seen[id] {
				continue
			}
			seen[id] = true
			subject, preview, vanished := op.snippet(email, terms)
			if vanished {
				missing = append(missing, requested)
				continue
			}
			list = append(list, object{"emailId": id, "subject": nullable(subject), "preview": nullable(preview)})
		}
	}
	return object{"list": list, "notFound": missing}, ""
}

type snippetTerms struct {
	subject, body []searchTerm
}

// Only positive text conditions can contribute a highlighted search term.
// The FilterOperator tree has already been checked by the query compiler.
func (t *snippetTerms) collect(filter rawObject, positive bool) {
	var children []rawObject
	if decodeStrict(filter["conditions"], &children) {
		var operator string
		_ = decodeStrict(filter["operator"], &operator)
		if operator == "NOT" {
			positive = !positive
		}
		for _, child := range children {
			t.collect(child, positive)
		}
		return
	}
	if !positive {
		return
	}
	var text, subject, body string
	_ = decodeStrict(filter["text"], &text)
	_ = decodeStrict(filter["subject"], &subject)
	_ = decodeStrict(filter["body"], &body)
	general := searchTerms(text)
	t.subject = append(t.subject, general...)
	t.subject = append(t.subject, searchTerms(subject)...)
	t.body = append(t.body, general...)
	t.body = append(t.body, searchTerms(body)...)
	var header []string
	if decodeStrict(filter["header"], &header) && len(header) == 2 && strings.EqualFold(header[0], "subject") {
		t.subject = append(t.subject, searchTerms(header[1])...)
	}
}

func (op *operation) snippet(email *emailMeta, terms snippetTerms) (subject, preview string, vanished bool) {
	if len(terms.subject)+len(terms.body) == 0 {
		return "", "", false
	}
	search := emailSearch{op: op, needsMIME: len(terms.body) > 0}
	if !search.load(email) {
		return "", "", search.failure == "notFound"
	}
	subject = highlightSnippet(decodeSearchHeader(lastHeaderValue(search.header, "Subject")), terms.subject, false)
	if search.needsMIME {
		for _, parts := range [][]*bodyPart{search.mime.plain, search.mime.html} {
			for _, part := range parts {
				for _, text := range searchableBodyPart(part) {
					if result := highlightSnippet(text, terms.body, true); result != "" {
						return subject, result, false
					}
				}
			}
		}
	}
	return subject, "", false
}

type snippetSpan struct{ start, end int }

func highlightSnippet(text string, terms []searchTerm, preview bool) string {
	if len(terms) == 0 {
		return ""
	}
	text = strings.ToValidUTF8(text, "\uFFFD")
	if preview {
		text = strings.Join(strings.Fields(text), " ")
	}
	folded := normalizeSearch(text)
	start, end := 0, len(folded)
	if preview {
		start = len(folded)
		for _, term := range terms {
			if first := term.find(folded, 0); first >= 0 {
				start = min(start, first)
			}
		}
		end = min(end, start+maxSnippetBytes)
	}
	spans := matchingSpans(folded, terms, start, end)
	if len(spans) == 0 {
		return ""
	}
	// Unicode simple lowercase preserves the rune count but may change the
	// octet count (for example, dotted capital I). Translate the offsets.
	displayOffset := len(text) - len(strings.TrimLeftFunc(text, unicode.IsSpace))
	foldedOffset := 0
	displayIndex := func(target int) int {
		for foldedOffset < target {
			r, width := utf8.DecodeRuneInString(text[displayOffset:])
			if unicode.IsSpace(r) {
				displayOffset = len(text) - len(strings.TrimLeftFunc(text[displayOffset:], unicode.IsSpace))
				foldedOffset++
			} else {
				displayOffset += width
				foldedOffset += utf8.RuneLen(unicode.ToLower(r))
			}
		}
		return displayOffset
	}
	for i, span := range spans {
		spans[i] = snippetSpan{displayIndex(span.start), displayIndex(span.end)}
	}
	if preview {
		return renderPreview(text, spans)
	}
	var output strings.Builder
	left := 0
	for _, span := range spans {
		output.WriteString(html.EscapeString(text[left:span.start]))
		output.WriteString(markSnippet(text[span.start:span.end]))
		left = span.end
	}
	output.WriteString(html.EscapeString(text[left:]))
	return output.String()
}

func matchingSpans(text string, terms []searchTerm, start, end int) []snippetSpan {
	ends := make([]int, end-start)
	seen := make(map[searchTerm]bool, len(terms))
	for _, term := range terms {
		if seen[term] {
			continue
		}
		seen[term] = true
		for offset := start; offset < end; {
			match := term.find(text, offset)
			if match < 0 || match+len(term.text) > end {
				break
			}
			ends[match-start] = max(ends[match-start], match+len(term.text))
			offset = match + 1
		}
	}
	var merged []snippetSpan
	for offset, end := range ends {
		if end == 0 {
			continue
		}
		start := start + offset
		last := len(merged) - 1
		if last >= 0 && start < merged[last].end {
			merged[last].end = max(merged[last].end, end)
		} else {
			merged = append(merged, snippetSpan{start, end})
		}
	}
	return merged
}

func markSnippet(text string) string { return "<mark>" + html.EscapeString(text) + "</mark>" }

func renderPreview(text string, spans []snippetSpan) string {
	const ellipsis = "…"
	first := spans[0]
	room := maxSnippetBytes - len(markSnippet(text[first.start:first.end])) - 2*len(ellipsis)
	if room < 0 {
		return ""
	}
	left := first.start
	for context := min(room, 48); left > 0; {
		_, width := utf8.DecodeLastRuneInString(text[:left])
		context -= len(html.EscapeString(text[left-width : left]))
		if context < 0 {
			break
		}
		left -= width
	}
	var output strings.Builder
	if left > 0 {
		output.WriteString(ellipsis)
	}
	limit := maxSnippetBytes - len(ellipsis)
	for _, span := range spans {
		gap := html.EscapeString(text[left:span.start])
		marked := markSnippet(text[span.start:span.end])
		if output.Len()+len(gap)+len(marked) > limit {
			return finishPreview(&output, text[left:span.start], ellipsis)
		}
		output.WriteString(gap)
		output.WriteString(marked)
		left = span.end
	}
	return finishPreview(&output, text[left:], ellipsis)
}

func finishPreview(output *strings.Builder, trailing, ellipsis string) string {
	limit := maxSnippetBytes - len(ellipsis)
	for len(trailing) > 0 {
		_, width := utf8.DecodeRuneInString(trailing)
		escaped := html.EscapeString(trailing[:width])
		if output.Len()+len(escaped) > limit {
			output.WriteString(ellipsis)
			break
		}
		output.WriteString(escaped)
		trailing = trailing[width:]
	}
	return output.String()
}
