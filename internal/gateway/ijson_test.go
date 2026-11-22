package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestJMAPRejectsNonIJSONBeforeDispatch(t *testing.T) {
	cfg := testConfig(t)
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	for _, test := range []struct{ name, payload string }{
		{"duplicate key", `{"a":1,"a":2}`},
		{"escaped duplicate key", `[{"a":1,"\u0061":2}]`},
		{"array nested duplicate key", `[0,{"a":1,"\u0061":2}]`},
		{"duplicate supplementary key", `{"😀":1,"\uD83D\uDE00":2}`},
		{"unpaired low surrogate", `{"a":"\uDC00"}`},
		{"unpaired high surrogate at end", `{"a":"\uD800"}`},
		{"unpaired high surrogate before escape", `{"a":"\uD800\n"}`},
		{"two high surrogates", `{"a":"\uD800\uD800"}`},
		{"noncharacter in key", `{"\uFDEF":null}`},
		{"raw noncharacter", `["` + string(rune(0xffff)) + `"]`},
		{"escaped supplementary noncharacter", `["\uDBFF\uDFFE"]`},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := gatewayRequest(g, http.MethodPost, "/jmap", cfg.Token, []byte(
				`{"using":["urn:ietf:params:jmap:core"],"methodCalls":[["Core/echo",{},"ok"]],"extension":`+test.payload+`}`))
			checkProblem(t, response, 400, "notJSON", "")
		})
	}
}

func TestIJSONCoreEchoAndResultReferences(t *testing.T) {
	cfg := testConfig(t)
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	payload := `{
	 "using":["urn:ietf:params:jmap:core"],"Using":{},"extension":{"ignored":true},
	 "createdIds":{},"methodCalls":[
	  ["Core/echo",{"text":"😀\uD800\uDC00\uFFFD\n\\","nested":[{"a":0},{"a":1}],"A":1,"a":9007199254740991,
	    "fraction":0.1234567890123456789,"/tilde~":true,"bad~2":null,"bad~":false},""],
	  ["Core/echo",{"text":"second"},""],
	  ["Core/echo",{"#whole":{"resultOf":"","name":"Core/echo","path":""},
	    "#escaped":{"resultOf":"","name":"Core/echo","path":"/~1tilde~0"}},"whole"],
	  ["Core/echo",{"a":null,"#a":{"resultOf":"","name":"Core/echo","path":"/a"}},"collision"],
	  ["Core/echo",{"#a":{"resultOf":"","name":"Core/echo","path":"/bad~2"}},"bad-escape"],
	  ["Core/echo",{"#a":{"resultOf":"","name":"Core/echo","path":"/bad~"}},"trailing-tilde"],
	  ["Core/echo",{"#a":{"resultOf":null,"name":"Core/echo","path":"/a"}},"null-result"],
	  ["Core/echo",{"#a":{"resultOf":"","name":"Core/echo"}},"missing-pointer"],
	  ["Core/echo",{"#a":{"ResultOf":"","name":"Core/echo","path":"/a"}},"wrong-case-result"],
	  ["",{},"unknown"]]
	 }`
	response := gatewayRequest(g, http.MethodPost, "/jmap", cfg.Token, []byte(payload))
	var reply struct {
		MethodResponses [][3]json.RawMessage
		CreatedIDs      map[string]string
	}
	if response.Code != 200 || !validIJSON(response.Body.Bytes()) ||
		json.Unmarshal(response.Body.Bytes(), &reply) != nil || len(reply.MethodResponses) != 10 || reply.CreatedIDs == nil {
		t.Fatalf("bad echo response: %d %s", response.Code, response.Body)
	}
	first := reply.MethodResponses[0]
	if string(first[0]) != `"Core/echo"` || string(first[2]) != `""` {
		t.Fatalf("empty call tag changed or first call failed: %s", first)
	}
	var resolved map[string]json.RawMessage
	third := reply.MethodResponses[2]
	if json.Unmarshal(third[1], &resolved) != nil || string(resolved["escaped"]) != "true" {
		t.Fatalf("root/escaped pointers: %s", third)
	}
	decode := func(raw json.RawMessage) map[string]any {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		var parsed map[string]any
		if err := decoder.Decode(&parsed); err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	if !reflect.DeepEqual(decode(resolved["whole"]), decode(first[1])) {
		t.Fatalf("root pointer changed the echoed object: %s", third)
	}
	for i, want := range []string{"invalidArguments", "invalidResultReference", "invalidResultReference", "invalidResultReference", "invalidResultReference", "invalidResultReference", "unknownMethod"} {
		row := reply.MethodResponses[i+3]
		if string(row[0]) != `"error"` || string(row[1]) != `{"type":"`+want+`"}` {
			t.Fatalf("invocation %d: %s, expected %s", i+3, row, want)
		}
	}
	var echoed map[string]json.RawMessage
	var text string
	if json.Unmarshal(first[1], &echoed) != nil || json.Unmarshal(echoed["text"], &text) != nil ||
		text != "😀𐀀�\n\\" || string(echoed["a"]) != "9007199254740991" || string(echoed["A"]) != "1" ||
		string(echoed["fraction"]) != "0.1234567890123456789" || string(echoed["nested"]) != `[{"a":0},{"a":1}]` {
		t.Fatalf("Core/echo changed valid I-JSON: %s", first)
	}
}

func TestResultReferenceBoundsExpansion(t *testing.T) {
	ref := object{"resultOf": "one", "name": "Core/echo", "path": "/value"}
	args := rawArgs(t, object{"#a": ref, "#b": ref})
	large := strings.Repeat("x", maxRequest/2)
	previous := map[string]invocationResult{"one": {"Core/echo", object{"value": large}}}
	if failure := resolveArgs(args, previous); failure != "invalidResultReference" {
		t.Fatalf("oversized result reference: %q", failure)
	}
}
