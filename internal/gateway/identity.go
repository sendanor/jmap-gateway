package gateway

import (
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strings"
)

const (
	identityID        = "sender"
	identityFile      = "identities.json"
	maxIdentities     = maxGet
	maxSignatureBytes = 16 << 10
	maxIdentityFile   = 8 << 20
)

type identityProfile struct {
	Name          *string
	Email         string
	ReplyTo       []address
	BCC           []address
	TextSignature string
	HTMLSignature string
}

func validIdentityAddress(value string) bool {
	return !strings.HasPrefix(value, "*@") && validAddress(value)
}

func (g *Gateway) allowsIdentity(value string) bool {
	return value == g.config.IdentityEmail || contains(g.config.IdentityAliases, value)
}

func (g *Gateway) identity(id string) (identityProfile, bool) {
	profile, found := g.identities[id]
	if id == identityID {
		profile.Email = g.config.IdentityEmail
		return profile, true
	}
	return profile, found
}

func (g *Gateway) identityRecords() map[string]object {
	profiles := make(map[string]object, len(g.identities)+1)
	primary, _ := g.identity(identityID)
	profiles[identityID] = primary.record(identityID, g.config.IdentityName)
	for id, profile := range g.identities {
		if id != identityID {
			profiles[id] = profile.record(id, "")
		}
	}
	return profiles
}

func (profile identityProfile) record(id, defaultName string) object {
	name := defaultName
	if profile.Name != nil {
		name = *profile.Name
	}
	return object{"id": id, "name": name, "email": profile.Email, "replyTo": profile.ReplyTo, "bcc": profile.BCC,
		"textSignature": profile.TextSignature, "htmlSignature": profile.HTMLSignature, "mayDelete": id != identityID}
}

func (g *Gateway) loadIdentities() error {
	g.identities = make(map[string]identityProfile)
	file, err := os.Open(filepath.Join(g.config.StateDir, identityFile))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return errors.New("cannot open identity state")
	}
	defer file.Close()
	raw, large, err := take(file, maxIdentityFile)
	var profiles map[string]identityProfile
	if err != nil || large || !decodeStrict(raw, &profiles) || profiles == nil || identityCount(profiles) > maxIdentities {
		return errors.New("invalid identity state")
	}
	pruned := false
	for id, profile := range profiles {
		if !jmapID.MatchString(id) || len(profile.invalid()) != 0 ||
			(id == identityID && profile.Email != "") || (id != identityID && !validIdentityAddress(profile.Email)) {
			return errors.New("invalid identity profile")
		}
		if id != identityID && !g.allowsIdentity(profile.Email) {
			delete(profiles, id)
			pruned = true
		}
	}
	if pruned {
		return g.saveIdentities(profiles)
	}
	g.identities = profiles
	return nil
}

func (g *Gateway) saveIdentities(next map[string]identityProfile) error {
	// Keep the visible state aligned with the last acknowledged durable write.
	if err := g.ledger.files.replace(g.config.StateDir, identityFile, ".identity-*", func(w io.Writer) error {
		return json.NewEncoder(w).Encode(next)
	}); err != nil {
		return errors.New("cannot persist identity state")
	}
	g.identities = next
	return nil
}

func identityCount(profiles map[string]identityProfile) int {
	if _, stored := profiles[identityID]; stored {
		return len(profiles)
	}
	return len(profiles) + 1
}

func (profile identityProfile) invalid() []string {
	var fields []string
	if profile.Name != nil && !safeDraftHeader(*profile.Name, 200) {
		fields = append(fields, "name")
	}
	for _, item := range []struct {
		key   string
		value []address
	}{{"replyTo", profile.ReplyTo}, {"bcc", profile.BCC}} {
		if !validIdentityAddresses(item.value) {
			fields = append(fields, item.key)
		}
	}
	for _, item := range []struct{ key, value string }{{"textSignature", profile.TextSignature}, {"htmlSignature", profile.HTMLSignature}} {
		if len(item.value) > maxSignatureBytes || strings.ContainsRune(item.value, 0) {
			fields = append(fields, item.key)
		}
	}
	return fields
}

func validIdentityAddresses(items []address) bool {
	if len(items) > maxSubmissionRecipients {
		return false
	}
	for _, item := range items {
		if !validAddress(item.Email) || item.Name != nil && !safeDraftHeader(*item.Name, 200) {
			return false
		}
	}
	return true
}

func editIdentity(id string, profile identityProfile, input json.RawMessage) (identityProfile, object) {
	var patch rawObject
	if !decodeStrict(input, &patch) || patch == nil {
		code := "invalidPatch"
		if id == "" {
			code = "invalidProperties"
		}
		return profile, object{"type": code}
	}
	var invalid []string
	if id == "" && patch["email"] == nil {
		invalid = append(invalid, "email")
	}
	for _, property := range sortedKeys(patch) {
		raw := patch[property]
		var valid bool
		switch property {
		case "email", "id", "name", "textSignature", "htmlSignature":
			var value *string
			valid = decodeStrict(raw, &value) && value != nil
			if valid {
				switch property {
				case "email":
					if id == "" {
						profile.Email = *value
						valid = validAddress(*value)
					} else {
						valid = *value == profile.Email
					}
				case "id":
					valid = id != "" && *value == id
				case "name":
					profile.Name = value
				case "textSignature":
					profile.TextSignature = *value
				case "htmlSignature":
					profile.HTMLSignature = *value
				}
			}
		case "replyTo", "bcc":
			var addresses []address
			valid = decodeStrict(raw, &addresses)
			if valid {
				if property == "replyTo" {
					profile.ReplyTo = addresses
				} else {
					profile.BCC = addresses
				}
			}
		case "mayDelete":
			var value *bool
			valid = decodeStrict(raw, &value) && value != nil && *value == (id != identityID)
		}
		if !valid {
			invalid = append(invalid, property)
		}
	}
	invalid = append(invalid, profile.invalid()...)
	if len(invalid) != 0 {
		return profile, object{"type": "invalidProperties", "properties": invalid}
	}
	return profile, nil
}

func (op *operation) setIdentities(raw rawObject) (object, string) {
	var args struct {
		accountArgs
		IfInState *string   `json:"ifInState"`
		Create    rawObject `json:"create"`
		Update    rawObject `json:"update"`
		Destroy   []string  `json:"destroy"`
	}
	if !decodeArgs(raw, &args) {
		return nil, "invalidArguments"
	}
	if len(args.Create)+len(args.Update)+len(args.Destroy) > maxSet {
		return nil, "requestTooLarge"
	}
	for key := range args.Create {
		if !jmapID.MatchString(key) {
			return nil, "invalidArguments"
		}
	}
	oldState := op.state("Identity")
	if args.IfInState != nil && *args.IfInState != oldState {
		return nil, "stateMismatch"
	}
	next := maps.Clone(op.g.identities)
	created, updated, notCreated, notUpdated, notDestroyed := object{}, object{}, object{}, object{}, object{}
	var destroyed []string
	references := make(map[string]string)
	for _, key := range sortedKeys(args.Create) {
		profile, failure := editIdentity("", identityProfile{}, args.Create[key])
		if failure == nil && !op.g.allowsIdentity(profile.Email) {
			failure = object{"type": "forbiddenFrom"}
		}
		if failure == nil && identityCount(next) >= maxIdentities {
			failure = object{"type": "overQuota"}
		}
		if failure != nil {
			notCreated[key] = failure
			continue
		}
		id := "i-" + randomID()
		next[id], references[key] = profile, id
		created[key] = object{"id": id, "mayDelete": true}
	}
	resolve := func(id string) string {
		if key, reference := strings.CutPrefix(id, "#"); reference && references[key] != "" {
			return references[key]
		}
		return op.resolveID(id)
	}
	for _, key := range sortedKeys(args.Update) {
		id := resolve(key)
		profile, exists := next[id]
		if id == identityID {
			profile.Email, exists = op.g.config.IdentityEmail, true
		}
		if !exists {
			notUpdated[key] = object{"type": "notFound"}
			continue
		}
		changed, failure := editIdentity(id, profile, args.Update[key])
		if failure != nil {
			notUpdated[key] = failure
			continue
		}
		if id == identityID {
			changed.Email = ""
		}
		next[id], updated[id] = changed, nil
	}
	for _, key := range args.Destroy {
		id := resolve(key)
		if id == identityID {
			notDestroyed[key] = object{"type": "forbidden"}
		} else if _, exists := next[id]; !exists {
			notDestroyed[key] = object{"type": "notFound"}
		} else {
			delete(next, id)
			destroyed = append(destroyed, id)
		}
	}
	if len(created)+len(updated)+len(destroyed) != 0 {
		if op.g.saveIdentities(next) != nil {
			return nil, "serverFail"
		}
		maps.Copy(op.created, references)
	}
	return object{"oldState": oldState, "newState": op.state("Identity"), "created": optionalSetMap(created),
		"updated": optionalSetMap(updated), "destroyed": destroyed, "notCreated": optionalSetMap(notCreated),
		"notUpdated": optionalSetMap(notUpdated), "notDestroyed": optionalSetMap(notDestroyed)}, ""
}
