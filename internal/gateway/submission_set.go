package gateway

import (
	"encoding/json"
	"maps"
	"reflect"
	"strings"
)

func validEmailActions(kind string, args setArgs) bool {
	if kind != "EmailSubmission" {
		return args.OnSuccessUpdateEmail == nil && args.OnSuccessDestroyEmail == nil
	}
	for id, patch := range args.OnSuccessUpdateEmail {
		if patch == nil || !jmapID.MatchString(strings.TrimPrefix(id, "#")) {
			return false
		}
	}
	for _, id := range args.OnSuccessDestroyEmail {
		if !jmapID.MatchString(strings.TrimPrefix(id, "#")) {
			return false
		}
	}
	return true
}

func createdSubmission(entry submissionRecord, raw json.RawMessage) object {
	result := submissionObject(entry)
	delete(result, "emailId")
	delete(result, "identityId")
	var input rawObject
	_ = json.Unmarshal(raw, &input) // The creation already validated this input.
	if value := input["envelope"]; value != nil && string(value) != "null" && entry.ReportKey == "" {
		delete(result, "envelope")
	}
	return result
}

func updateSubmission(entry submissionRecord, raw json.RawMessage) object {
	if entry.ID == "" {
		return object{"type": "notFound"}
	}
	var patch map[string]any
	if json.Unmarshal(raw, &patch) != nil || patch == nil {
		return object{"type": "invalidPatch"}
	}
	// The current gateway only exposes final submissions. An unchanged patch
	// is still a successful update, including a whole record read by Get.
	serialized, _ := json.Marshal(submissionObject(entry))
	var current map[string]any
	_ = json.Unmarshal(serialized, &current)
	invalid := make([]string, 0)
	for _, path := range sortedKeys(patch) {
		if !validPointerEscapes(path) {
			return object{"type": "invalidPatch"}
		}
		segments := strings.Split(path, "/")
		parent := current
		for i, segment := range segments[:len(segments)-1] {
			if _, overlap := patch[strings.Join(segments[:i+1], "/")]; overlap {
				return object{"type": "invalidPatch"}
			}
			next, parentExists := parent[unescapePointerToken(segment)].(map[string]any)
			if !parentExists {
				return object{"type": "invalidPatch"}
			}
			parent = next
		}
		field := unescapePointerToken(segments[len(segments)-1])
		if !reflect.DeepEqual(parent[field], patch[path]) {
			invalid = append(invalid, path)
		}
	}
	if len(invalid) != 0 {
		return object{"type": "invalidProperties", "properties": invalid}
	}
	return nil
}

func (l *ledger) destroySubmission(id string) string {
	for key, saved := range l.records {
		if saved.ID != id || saved.Status != "accepted" {
			continue
		}
		entry := saved
		entry.Status = "destroyed"
		l.records[key] = entry
		replaced, err := l.persist()
		if err == nil {
			return ""
		}
		if replaced {
			return "serverPartialFail"
		}
		l.records[key] = saved
		return "serverFail"
	}
	return "notFound"
}

func (op *operation) applySubmissionEmailActions(args setArgs, success map[string]string) {
	patches := make(map[string]rawObject)
	for _, id := range sortedKeys(args.OnSuccessUpdateEmail) {
		if emailID := success[op.resolveID(id)]; emailID != "" {
			if patches[emailID] == nil {
				patches[emailID] = make(rawObject)
			}
			maps.Copy(patches[emailID], args.OnSuccessUpdateEmail[id])
		}
	}
	destroy := make(map[string]bool)
	for _, id := range args.OnSuccessDestroyEmail {
		if emailID := success[op.resolveID(id)]; emailID != "" {
			destroy[emailID] = true
		}
	}
	if len(patches)+len(destroy) == 0 {
		return
	}

	updateArg, _ := json.Marshal(patches)
	destroyArg, _ := json.Marshal(sortedKeys(destroy))
	op.implicit = op.implicitEmailSet(rawObject{"update": updateArg, "destroy": destroyArg})
}

func (op *operation) implicitEmailSet(raw rawObject) *invocationResult {
	result, failure := op.set("Email", raw)
	name := "Email/set"
	if failure != "" {
		name, result = methodError(failure)
	} else {
		result["accountId"] = op.g.config.AccountID
	}
	return &invocationResult{name, result}
}
