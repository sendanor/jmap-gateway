package gateway

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func buildDraftPartFixture(t *testing.T, fields object) ([]byte, object) {
	t.Helper()
	const sender = "sender@example.test"
	input := draftFixture("drafts", sender)
	input["bodyValues"] = object{"plain": object{"value": "fixture text"}}
	for key, value := range fields {
		input[key] = value
	}
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	draft, failure := makeDraft(data, time.Now(), func(email string) bool { return email == sender }, nil)
	return draft.raw, failure
}

func TestDraftPartHeaderNormalizationAndConflicts(t *testing.T) {
	wire, failure := buildDraftPartFixture(t, object{"bodyStructure": object{
		"header:Content-Type": " multipart/related; boundary=client-boundary", "header:X-Root": " original",
		"subParts": []object{{"header:Content-Type": " text/plain; charset=\"UTF-8\"",
			"partId": "plain", "header:Content-Description:asText": "Terve ä"}},
	}})
	if failure != nil {
		t.Fatalf("header-specified multipart: %v", failure)
	}
	if strings.Contains(string(wire), "client-boundary") || !strings.Contains(string(wire), "type=\"text/plain\"") ||
		!strings.Contains(string(wire), "Content-Type: text/plain; charset=\"UTF-8\"\r\n") ||
		!strings.Contains(string(wire), "X-Root: original\r\n") {
		t.Fatalf("invalid root or leaf Content-Type: %q", wire)
	}
	parsed, code := parseMIME(wire, "e-test")
	if code != "" || len(parsed.plain) != 1 || string(parsed.plain[0].Value) != "fixture text" {
		t.Fatalf("header-specified MIME did not parse: %s", code)
	}
	headers := parsed.plain[0].Data["headers"].([]object)
	out := object{}
	renderHeaderProjections(out, headers, []headerProjection{
		{property: "description", name: "content-description", form: "asText"},
	})
	if out["description"] != "Terve ä" {
		t.Fatalf("wrong description text: %v", out)
	}

	for _, test := range []struct {
		name   string
		fields object
	}{
		{"empty shortcut", object{"textBody": []any{}}},
		{"multiple shortcut parts", object{"htmlBody": []object{{"partId": "plain", "type": "text/html"}, {"partId": "plain", "type": "text/html"}}}},
		{"null part", object{"textBody": []any{nil}}},
		{"malformed selector", object{"textBody": []object{{"partId": "plain", "type": "text/plain", "header:": " text"}}}},
		{"duplicate selector", object{"textBody": []object{{"partId": "plain", "type": "text/plain", "header:X-Part": " text", "header:x-Part:asText": "again"}}}},
		{"missing type", object{"textBody": []object{{"partId": "plain"}}}},
		{"alias conflict", object{"textBody": []object{{"partId": "plain", "type": "text/plain", "header:Content-Type": " text/plain"}}}},
		{"disposition alias conflict", object{"textBody": []object{{"partId": "plain", "type": "text/plain", "name": nil, "header:Content-Disposition": " inline"}}}},
		{"empty type", object{"textBody": []object{{"partId": "plain", "header:Content-Type": ""}}}},
		{"bad raw value", object{"textBody": []object{{"partId": "plain", "type": "text/plain", "header:X-Part": " test\r\nCc: x@example.test"}}}},
		{"headers array", object{"textBody": []object{{"partId": "plain", "type": "text/plain", "headers": []object{}}}}},
		{"caller-selected encoding", object{"textBody": []object{{"partId": "plain", "type": "text/plain", "header:Content-Transfer-Encoding": " base64"}}}},
		{"repeated structural header", object{"textBody": []object{{"partId": "plain", "header:Content-Type:all": []string{" text/plain", " text/plain"}}}}},
		{"invalid disposition", object{"textBody": []object{{"partId": "plain", "type": "text/plain", "header:Content-Disposition": " inline; ="}}}},
		{"named charset on body value", object{"textBody": []object{{"partId": "plain", "type": "text/plain", "charset": "utf-8"}}}},
		{"invalid charset", object{"textBody": []object{{"partId": "plain", "header:Content-Type": " text/plain; charset=iso-8859-1"}}}},
		{"root field shadows message", object{"bodyStructure": object{"type": "text/plain", "partId": "plain", "header:Subject": " conflict"}}},
		{"root field shadows generated Date", object{"textBody": []object{{"partId": "plain", "type": "text/plain", "header:Date": " Tue, 24 Nov 2026 10:00:00 +0000"}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, failure := buildDraftPartFixture(t, test.fields)
			if got != nil || failure["type"] != "invalidProperties" {
				t.Fatalf("unexpected result for invalid part: %v", failure)
			}
		})
	}
}
