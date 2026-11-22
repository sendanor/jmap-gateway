package gateway

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
)

func TestSubmissionEmailActionsOverTLS(t *testing.T) {
	for _, smtpFailure := range []string{"", "rcpt", "lost-reply"} {
		t.Run("smtp-"+smtpFailure, func(t *testing.T) {
			config := testConfig(t)
			config.DraftsMailbox = "Drafts"
			cert, ca := testTLS(t)
			caps := imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapUIDPlus: {}, imap.CapMove: {}}
			config.IMAP.Address, _ = serveTestIMAP(t, config.IMAP, cert, caps, nil)
			config.IMAP.CAFile, config.SMTP.CAFile = ca, ca
			address, relay := serveTestSMTP(t, config.SMTP, cert, smtpFailure)
			config.SMTP.Address = address
			g, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			defer g.Close()

			drafts, sent := mailboxID(config.AccountID, "Drafts"), mailboxID(config.AccountID, "Plain")
			draft := draftFixture(drafts, config.IdentityEmail)
			draft["keywords"] = object{"$draft": true}
			draft["textBody"] = []object{{"partId": "text", "type": "text/plain"}}
			draft["bodyValues"] = object{"text": object{"value": "Hello"}}
			created := gatewayCalls(t, g, config.Token, [3]any{"Email/set", object{
				"accountId": config.AccountID, "create": object{"draft": draft},
			}, "create"})[0]
			if created.Name != "Email/set" || created.Args["created"] == nil {
				t.Fatalf("draft creation failed: %v", created)
			}
			id := created.Args["created"].(map[string]any)["draft"].(map[string]any)["id"].(string)

			send := object{"accountId": config.AccountID,
				"create": object{"send": object{"emailId": id, "identityId": identityID}},
				"onSuccessUpdateEmail": object{"#send": object{
					"mailboxIds/" + drafts: nil, "mailboxIds/" + sent: true, "keywords/$draft": nil,
				}},
				"onSuccessDestroyEmail": []string{"#unrelated"}}
			read := [3]any{"Email/get", object{"accountId": config.AccountID, "ids": []string{id}, "properties": []string{"mailboxIds", "keywords"}}, "read"}
			if smtpFailure != "" {
				flow := gatewayCalls(t, g, config.Token, [3]any{"EmailSubmission/set", send, "send"}, read)
				entry := flow[1].Args["list"].([]any)[0].(map[string]any)
				if flow[0].Args["notCreated"] == nil || !reflect.DeepEqual(entry["mailboxIds"], map[string]any{drafts: true}) ||
					entry["keywords"].(map[string]any)["$draft"] != true {
					t.Fatalf("failed submission changed its draft: %v", flow)
				}
				return
			}

			// The first response with the "send" tag is the result reference target.
			refer := [3]any{"Core/echo", object{"#submission": object{
				"resultOf": "send", "name": "EmailSubmission/set", "path": "/created/send/id",
			}}, "ref"}
			flow := emailActionCalls(t, g, config.Token, [3]any{"EmailSubmission/set", send, "send"}, refer, read)
			if len(flow) != 4 || flow[0].Name != "EmailSubmission/set" || flow[1].Name != "Email/set" ||
				flow[0].Tag != "send" || flow[1].Tag != "send" || flow[1].Args["accountId"] != config.AccountID ||
				flow[1].Args["updated"] == nil || flow[1].Args["newState"] == flow[1].Args["oldState"] ||
				flow[2].Name != "Core/echo" || flow[2].Args["submission"] == nil {
				t.Fatalf("incorrect implicit response sequence: %v", flow)
			}
			entry := flow[3].Args["list"].([]any)[0].(map[string]any)
			if !reflect.DeepEqual(entry["mailboxIds"], map[string]any{sent: true}) || entry["keywords"].(map[string]any)["$draft"] != nil {
				t.Fatalf("submitted draft was not filed and unflagged: %v", entry)
			}
			if err := <-relay.done; err != nil {
				t.Fatal(err)
			}
			submission := flow[2].Args["submission"].(string)
			send["onSuccessUpdateEmail"] = object{"#send": object{"mailboxIds": object{"missing": true}}}
			failedAction := emailActionCalls(t, g, config.Token, [3]any{"EmailSubmission/set", send, "send"})
			if len(failedAction) != 2 || failedAction[0].Args["created"] == nil || failedAction[1].Args["notUpdated"] == nil {
				t.Fatalf("filing failure rewrote the SMTP outcome: %v", failedAction)
			}
			delete(send, "onSuccessUpdateEmail")
			send["onSuccessDestroyEmail"] = []string{submission}
			destroyed := emailActionCalls(t, g, config.Token, [3]any{"EmailSubmission/set", send, "send"}, read)
			if len(destroyed) != 3 || !reflect.DeepEqual(destroyed[1].Args["destroyed"], []any{id}) ||
				!reflect.DeepEqual(destroyed[2].Args["notFound"], []any{id}) {
				t.Fatalf("accepted replay did not destroy its Email: %v", destroyed)
			}
		})
	}
}

type emailActionResponse struct {
	Name string
	Args object
	Tag  string
}

func emailActionCalls(t *testing.T, g *Gateway, token string, calls ...[3]any) []emailActionResponse {
	t.Helper()
	raw, err := json.Marshal(object{"using": []string{core, mailCapability, submissionCapability}, "methodCalls": calls})
	if err != nil {
		t.Fatal(err)
	}
	response := gatewayRequest(g, http.MethodPost, "/jmap", token, raw)
	var envelope struct {
		Responses [][3]json.RawMessage `json:"methodResponses"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &envelope) != nil {
		t.Fatalf("JMAP HTTP %d, body %s", response.Code, response.Body)
	}
	results := make([]emailActionResponse, 0, len(envelope.Responses))
	for _, row := range envelope.Responses {
		var item emailActionResponse
		if json.Unmarshal(row[0], &item.Name) != nil || json.Unmarshal(row[1], &item.Args) != nil || json.Unmarshal(row[2], &item.Tag) != nil {
			t.Fatalf("invalid invocation response: %s", row)
		}
		results = append(results, item)
	}
	return results
}

func TestSubmissionEmailActionMethodError(t *testing.T) {
	config := testConfig(t)
	g, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	g.ledger.records["key"] = submissionRecord{ID: "submission", EmailID: "message", Status: "accepted"}
	op := operation{g: g, snapshotFailure: "serverUnavailable", created: map[string]string{"send": "submission"}}
	op.applySubmissionEmailActions(setArgs{OnSuccessDestroyEmail: []string{"#send"}}, map[string]string{"submission": "message"})
	if op.implicit == nil || op.implicit.name != "error" || op.implicit.args["type"] != "serverUnavailable" {
		t.Fatalf("missing implicit method error: %+v", op.implicit)
	}
}

func TestSubmissionLifecyclePreservesReplayAcrossRestart(t *testing.T) {
	cfg := testConfig(t)
	cfg.DraftsMailbox = "Drafts"
	cert, ca := testTLS(t)
	caps := imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapUIDPlus: {}}
	cfg.IMAP.Address, _ = serveTestIMAP(t, cfg.IMAP, cert, caps, nil)
	cfg.IMAP.CAFile, cfg.SMTP.CAFile = ca, ca
	address, relay := serveTestSMTP(t, cfg.SMTP, cert, "")
	cfg.SMTP.Address = address
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if g != nil {
			_ = g.Close()
		}
	}()

	call := func(method string, args object) [3]any {
		args["accountId"] = cfg.AccountID
		return [3]any{method, args, method}
	}
	draft := draftFixture(mailboxID(cfg.AccountID, "Drafts"), cfg.IdentityEmail)
	draft["textBody"] = []object{{"partId": "text", "type": "text/plain"}}
	draft["bodyValues"] = object{"text": object{"value": "Hello"}}
	created := gatewayCalls(t, g, cfg.Token, call("Email/set", object{"create": object{"new": draft}}))[0].Args
	emailID := created["created"].(map[string]any)["new"].(map[string]any)["id"].(string)
	request := object{"emailId": emailID, "identityId": identityID}
	sent := gatewayCalls(t, g, cfg.Token, call("EmailSubmission/set", object{"create": object{"send": request}}))[0].Args
	if err := <-relay.done; err != nil {
		t.Fatal(err)
	}
	record := sent["created"].(map[string]any)["send"].(map[string]any)
	submissionID := record["id"].(string)
	if record["envelope"] == nil || record["sendAt"] == nil || record["undoStatus"] != "final" ||
		record["threadId"] == nil || !reflect.DeepEqual(record["dsnBlobIds"], []any{}) {
		t.Fatalf("missing server-set submission properties: %v", record)
	}
	before := gatewayCalls(t, g, cfg.Token, call("EmailSubmission/get", object{}), call("EmailSubmission/query", object{}))
	list := before[0].Args["list"].([]any)
	known := list[0].(map[string]any)
	state, queryState := before[0].Args["state"], before[1].Args["queryState"]
	mismatch := gatewayCalls(t, g, cfg.Token, call("EmailSubmission/set", object{"ifInState": "wrong", "destroy": []string{submissionID}}))[0]
	if mismatch.Name != "error" || mismatch.Args["type"] != "stateMismatch" {
		t.Fatalf("stale state removed a submission: %v", mismatch)
	}
	updated := emailActionCalls(t, g, cfg.Token, call("EmailSubmission/set", object{
		"update":               object{submissionID: known},
		"onSuccessUpdateEmail": object{submissionID: object{"keywords/$seen": true}},
	}))
	if len(updated) != 2 || updated[1].Name != "Email/set" ||
		!reflect.DeepEqual(updated[0].Args["updated"], map[string]any{submissionID: nil}) ||
		updated[0].Args["newState"] != state ||
		!reflect.DeepEqual(updated[1].Args["updated"], map[string]any{emailID: nil}) {
		t.Fatalf("unchanged update and follow-up: %v", updated)
	}
	for _, item := range []struct {
		patch any
		kind  string
	}{
		{nil, "invalidPatch"},
		{object{"bad~2": nil}, "invalidPatch"},
		{object{"envelope": known["envelope"], "envelope/mailFrom": nil}, "invalidPatch"},
		{object{"envelope/rcptTo/0": nil}, "invalidPatch"},
		{object{"undoStatus": "canceled", "sendAt": "2026-01-01T00:00:00Z"}, "invalidProperties"},
	} {
		refused := gatewayCalls(t, g, cfg.Token, call("EmailSubmission/set", object{"update": object{submissionID: item.patch}}))[0].Args
		failure := refused["notUpdated"].(map[string]any)[submissionID].(map[string]any)
		if failure["type"] != item.kind || refused["newState"] != state {
			t.Fatalf("incorrect update failure: %v", refused)
		}
		if item.kind == "invalidProperties" && !reflect.DeepEqual(failure["properties"], []any{"sendAt", "undoStatus"}) {
			t.Fatalf("missing invalid properties: %v", failure)
		}
	}
	same := gatewayCalls(t, g, cfg.Token, call("EmailSubmission/set", object{
		"update": object{submissionID: object{"envelope/mailFrom/email": cfg.IdentityEmail, "missing~1leaf": nil}},
	}))[0].Args
	if !reflect.DeepEqual(same["updated"], map[string]any{submissionID: nil}) || same["newState"] != state {
		t.Fatalf("wrong computed patch outcome: %v", same)
	}

	destroyed := emailActionCalls(t, g, cfg.Token, call("EmailSubmission/set", object{
		"create":               object{"again": request},
		"destroy":              []string{"#again", "missing"},
		"ifInState":            state,
		"onSuccessUpdateEmail": object{"#again": object{"keywords/$flagged": true}},
	}))
	if len(destroyed) != 2 || destroyed[1].Name != "Email/set" ||
		!reflect.DeepEqual(destroyed[0].Args["destroyed"], []any{submissionID}) ||
		destroyed[0].Args["newState"] == state ||
		destroyed[0].Args["notDestroyed"].(map[string]any)["missing"].(map[string]any)["type"] != "notFound" {
		t.Fatalf("destruction by creation reference: %v", destroyed)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	g, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	after := gatewayCalls(t, g, cfg.Token,
		call("EmailSubmission/get", object{"ids": []string{submissionID}}),
		call("EmailSubmission/changes", object{"sinceState": state}),
		call("EmailSubmission/queryChanges", object{"sinceQueryState": queryState}),
		call("Email/get", object{"ids": []string{emailID}, "properties": []string{"keywords"}}),
		call("EmailSubmission/set", object{"create": object{"retry": request}, "update": object{submissionID: object{}}}))
	if !reflect.DeepEqual(after[0].Args["notFound"], []any{submissionID}) ||
		!reflect.DeepEqual(after[1].Args["destroyed"], []any{submissionID}) || after[1].Args["newState"] != destroyed[0].Args["newState"] ||
		!reflect.DeepEqual(after[2].Args["removed"], []any{submissionID}) {
		t.Fatalf("deleted history not synchronized across restart: %v", after)
	}
	keywords := after[3].Args["list"].([]any)[0].(map[string]any)["keywords"].(map[string]any)
	retry := after[4].Args["notCreated"].(map[string]any)["retry"].(map[string]any)
	if keywords["$seen"] != true || keywords["$flagged"] != true || retry["type"] != "forbiddenToSend" ||
		after[4].Args["notUpdated"].(map[string]any)[submissionID].(map[string]any)["type"] != "notFound" {
		t.Fatalf("history deletion lost the message or its replay reservation: %v", after)
	}
}

func TestSubmissionDestructionStorageFailures(t *testing.T) {
	for _, afterRename := range []bool{false, true} {
		cfg := testConfig(t)
		g, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		l := g.ledger
		entry := submissionRecord{ID: "record", EmailID: "message", IdentityID: identityID,
			From: cfg.IdentityEmail, To: "recipient@example.test", SendAt: time.Now(), Status: "accepted"}
		l.records["reservation"] = entry
		if err := l.save(); err != nil {
			t.Fatal(err)
		}
		want, visible := "serverFail", "accepted"
		if afterRename {
			l.files.openDirectory = func(string) (syncCloser, error) { return nil, diskError }
			want, visible = "serverPartialFail", "destroyed"
		} else {
			l.files.rename = func(string, string) error { return diskError }
		}
		result := gatewayCalls(t, g, cfg.Token, [3]any{"EmailSubmission/set", object{
			"accountId": cfg.AccountID, "destroy": []string{entry.ID},
		}, "failure"})[0].Args
		if result["destroyed"] != nil || result["notDestroyed"].(map[string]any)[entry.ID].(map[string]any)["type"] != want ||
			l.records["reservation"].Status != visible || !l.failed {
			t.Fatalf("inconsistent outcome after ledger failure: %v", result)
		}
		if err := g.Close(); err != nil {
			t.Fatal(err)
		}
		g, err = New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if g.ledger.records["reservation"].Status != visible {
			t.Fatal("in-memory and on-disk outcomes disagree")
		}
		if err := g.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
