package gateway

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestEmailSubmissionQueryFiltersSortAndChanges(t *testing.T) {
	config := testConfig(t)
	g, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	earlyEmail, lateEmail := "e-aaaa", "e-zzzz"
	g.ledger.records["early"] = submissionRecord{ID: "early", EmailID: earlyEmail, IdentityID: "sender", Status: "accepted",
		SendAt: time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)}
	g.ledger.records["late"] = submissionRecord{ID: "late", EmailID: lateEmail, IdentityID: "sender", Status: "accepted",
		SendAt: time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)}
	g.ledger.records["pending"] = submissionRecord{ID: "pending", EmailID: "e-other", IdentityID: "sender", Status: "pending"}
	check := func(args object, expected ...string) object {
		t.Helper()
		args["accountId"] = config.AccountID
		query := gatewayCalls(t, g, config.Token, [3]any{"EmailSubmission/query", args, "query"})[0]
		ids := make([]any, 0, len(expected))
		for _, id := range expected {
			ids = append(ids, id)
		}
		if query.Name != "EmailSubmission/query" || !reflect.DeepEqual(query.Args["ids"], ids) ||
			query.Args["canCalculateChanges"] != true {
			t.Fatalf("unexpected SMTP submission query: %v", query)
		}
		return query.Args
	}
	check(object{}, "early", "late")
	check(object{"sort": []object{{"property": "emailId"}}}, "early", "late")
	check(object{"sort": []object{{"property": "emailId", "collation": octetCollation}}}, "early", "late")
	check(object{"sort": []object{{"property": "threadId", "isAscending": false}}}, "late", "early")
	check(object{"sort": []object{{"property": "sentAt", "isAscending": false}}}, "late", "early")
	check(object{"filter": object{"emailIds": []string{earlyEmail}, "after": "2026-11-12T12:00:00Z", "before": "2026-11-14T12:00:00Z"}}, "early")
	check(object{"filter": object{"undoStatus": "pending"}})
	filter := object{"operator": "OR", "conditions": []object{
		{"identityIds": []string{"sender"}, "threadIds": []string{"t-zzzz"}},
		{"undoStatus": "final", "before": "2026-11-13T00:00:00Z"},
	}}
	order := []object{{"property": "sentAt"}}
	before := check(object{"filter": filter, "sort": order}, "early", "late")
	// This record follows both known positions and would be omitted if the
	// mutable undoStatus filter incorrectly honored upToId.
	g.ledger.records["later"] = submissionRecord{ID: "later", EmailID: lateEmail, IdentityID: "sender", Status: "accepted",
		SendAt: time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)}
	result := gatewayCalls(t, g, config.Token, [3]any{"EmailSubmission/queryChanges", object{
		"accountId": config.AccountID, "filter": filter, "sort": order, "sinceQueryState": before["queryState"], "upToId": "early",
	}, "delta"})[0]
	if result.Name != "EmailSubmission/queryChanges" ||
		!reflect.DeepEqual(result.Args["added"], []any{map[string]any{"id": "later", "index": float64(2)}}) {
		t.Fatalf("submission query changes missing received acceptance: %v", result)
	}
}

func TestEmailSubmissionQueryValidation(t *testing.T) {
	config := testConfig(t)
	g, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	op := operation{g: g}
	for _, test := range []struct {
		args object
		want string
	}{
		{object{"sort": []object{{"property": "name"}}}, "unsupportedSort"},
		{object{"sort": []object{{"property": "threadId", "collation": "unknown"}}}, "unsupportedSort"},
		{object{"filter": object{"identityIds": nil}}, "invalidArguments"},
		{object{"filter": object{"emailIds": []string{"bad id"}}}, "invalidArguments"},
		{object{"filter": object{"undoStatus": ""}}, "invalidArguments"},
		{object{"filter": object{"before": "2026-11-12T08:00:00+02:00"}}, "invalidArguments"},
		{object{"filter": object{"after": "not-a-dateZ"}}, "invalidArguments"},
		{object{"filter": object{"mailFrom": "sender@example.test"}}, "unsupportedFilter"},
		{object{"filter": object{"operator": "AND", "conditions": []object{{"threadIds": []string{strings.Repeat("x", 256)}}}}}, "invalidArguments"},
	} {
		if _, failure := op.executeQuery("EmailSubmission", rawArgs(t, test.args)); failure != test.want {
			t.Fatalf("submission query returned %q, want %q", failure, test.want)
		}
	}
}
