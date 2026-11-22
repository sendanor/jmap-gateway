package gateway

import (
	"crypto/subtle"
	"encoding/json"
	"maps"
	"strings"
	"time"
)

func (op *operation) pushMethod(name string, raw rawObject) (object, string) {
	p := op.g.push
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failed || p.prune(time.Now()) != nil {
		return nil, "serverFail"
	}
	if name == "PushSubscription/get" {
		return op.getPush(raw)
	}
	return op.setPush(raw)
}

func (op *operation) getPush(raw rawObject) (object, string) {
	var args struct {
		IDs        []string `json:"ids"`
		Properties []string `json:"properties"`
	}
	if !validGetArgumentNames(raw, "PushSubscription") || !decodeArgs(raw, &args) {
		return nil, "invalidArguments"
	}
	if failure := validateGetIDs(args.IDs); failure != "" {
		return nil, failure
	}
	for _, name := range args.Properties {
		switch name {
		case "url", "keys":
			return nil, "forbidden"
		case "id", "deviceClientId", "verificationCode", "expires", "types":
		default:
			return nil, "invalidArguments"
		}
	}
	records := op.g.push.records
	if args.IDs == nil {
		args.IDs = sortedKeys(records)
	}
	list, notFound := []object{}, []string{}
	for _, lookup := range op.uniqueGetIDs(args.IDs) {
		id := lookup.resolved
		if sub, ok := records[id]; ok {
			var code any
			if sub.Verified {
				code = sub.Code
			}
			data := object{"id": id, "deviceClientId": sub.Device, "verificationCode": code,
				"expires": sub.Expires.Format(time.RFC3339), "types": sub.Types}
			list = append(list, project(data, args.Properties))
		} else {
			notFound = append(notFound, lookup.requested)
		}
	}
	return object{"list": list, "notFound": notFound}, ""
}

func (op *operation) setPush(raw rawObject) (object, string) {
	var args struct {
		Create  rawObject `json:"create"`
		Update  rawObject `json:"update"`
		Destroy []string  `json:"destroy"`
	}
	if !decodeArgs(raw, &args) {
		return nil, "invalidArguments"
	}
	if len(args.Create)+len(args.Update)+len(args.Destroy) > maxSet {
		return nil, "requestTooLarge"
	}
	for id := range args.Create {
		if !jmapID.MatchString(id) {
			return nil, "invalidArguments"
		}
	}
	p := op.g.push
	next := maps.Clone(p.records)
	created, updated, notCreated, notUpdated, notDestroyed := object{}, object{}, object{}, object{}, object{}
	var destroyed []string
	newIDs := make(map[string]string)
	changed := false
	budget := p.verificationBudget(time.Now())
	for _, key := range sortedKeys(args.Create) {
		sub, failure := p.create(args.Create[key], time.Now())
		if failure == nil && len(next) >= maxPushRecords {
			failure = object{"type": "overQuota"}
		}
		if failure == nil && len(newIDs) >= budget {
			failure = object{"type": "rateLimit"}
		}
		if failure != nil {
			notCreated[key] = failure
			continue
		}
		id := randomID()
		newIDs[key] = id
		next[id] = sub
		created[key] = object{"id": id, "expires": sub.Expires.Format(time.RFC3339)}
		changed = true
	}
	resolve := func(id string) string {
		if key, reference := strings.CutPrefix(id, "#"); reference && newIDs[key] != "" {
			return newIDs[key]
		}
		return op.resolveID(id)
	}
	for _, key := range sortedKeys(args.Update) {
		id := resolve(key)
		sub, exists := next[id]
		if !exists {
			notUpdated[key] = object{"type": "notFound"}
			continue
		}
		if nextSub, failure := sub.updated(id, args.Update[key], time.Now()); failure != nil {
			notUpdated[key] = failure
		} else {
			next[id] = nextSub
			updated[id] = nil
			changed = true
		}
	}
	for _, key := range args.Destroy {
		id := resolve(key)
		if _, exists := next[id]; !exists {
			notDestroyed[key] = object{"type": "notFound"}
			continue
		}
		delete(next, id)
		destroyed = append(destroyed, id)
		changed = true
	}
	if changed && p.save(next) != nil {
		return nil, "serverFail"
	}
	for _, key := range sortedKeys(newIDs) {
		id := newIDs[key]
		op.created[key] = id
		if sub, exists := next[id]; exists {
			p.verifies = append(p.verifies, time.Now())
			p.post(op.ctx, sub, object{"@type": "PushVerification", "pushSubscriptionId": id, "verificationCode": sub.Code})
		}
	}
	return object{"created": optionalSetMap(created), "updated": optionalSetMap(updated), "destroyed": destroyed,
		"notCreated": optionalSetMap(notCreated), "notUpdated": optionalSetMap(notUpdated), "notDestroyed": optionalSetMap(notDestroyed)}, ""
}

func (p *pushStore) create(raw json.RawMessage, now time.Time) (pushSubscription, object) {
	var input struct {
		Device  string    `json:"deviceClientId"`
		URL     string    `json:"url"`
		Keys    *pushKeys `json:"keys"`
		Expires *string   `json:"expires"`
		Types   []string  `json:"types"`
		Code    *string   `json:"verificationCode"`
	}
	if !decodeStrict(raw, &input) {
		return pushSubscription{}, object{"type": "invalidProperties"}
	}
	if input.Device == "" || !safeDraftHeader(input.Device, 255) {
		return pushSubscription{}, invalidPush("deviceClientId")
	}
	if _, ok := pushURL(input.URL); !ok {
		return pushSubscription{}, invalidPush("url")
	}
	if !p.allows(input.URL) {
		return pushSubscription{}, object{"type": "forbidden"}
	}
	if input.Code != nil {
		return pushSubscription{}, invalidPush("verificationCode")
	}
	if input.Keys != nil {
		if _, _, ok := input.Keys.decode(); !ok {
			return pushSubscription{}, invalidPush("keys")
		}
	}
	expires, valid := pushExpiration(input.Expires, now)
	if !valid {
		return pushSubscription{}, invalidPush("expires")
	}
	if !validPushTypes(input.Types) {
		return pushSubscription{}, invalidPush("types")
	}
	return pushSubscription{Device: input.Device, URL: input.URL, Keys: input.Keys,
		Expires: expires, Types: input.Types, Code: randomID()}, nil
}

func (sub pushSubscription) updated(id string, raw json.RawMessage, now time.Time) (pushSubscription, object) {
	var patch rawObject
	if !decodeStrict(raw, &patch) || patch == nil {
		return sub, object{"type": "invalidPatch"}
	}
	for _, name := range sortedKeys(patch) {
		value := patch[name]
		switch name {
		case "verificationCode":
			var code *string
			if !decodeStrict(value, &code) {
				return sub, invalidPush(name)
			}
			if code == nil && !sub.Verified {
				continue
			}
			if code == nil || subtle.ConstantTimeCompare([]byte(*code), []byte(sub.Code)) != 1 {
				return sub, invalidPush(name)
			}
			sub.Verified = true
		case "expires":
			var rawDate *string
			if !decodeStrict(value, &rawDate) {
				return sub, invalidPush(name)
			}
			date, valid := pushExpiration(rawDate, now)
			if !valid {
				return sub, invalidPush(name)
			}
			sub.Expires = date
		case "types":
			var types []string
			if !decodeStrict(value, &types) || !validPushTypes(types) {
				return sub, invalidPush(name)
			}
			sub.Types = types
		case "id", "deviceClientId", "url":
			var expected = map[string]string{"id": id, "deviceClientId": sub.Device, "url": sub.URL}
			var current string
			if !decodeStrict(value, &current) || current != expected[name] {
				return sub, invalidPush(name)
			}
		case "keys":
			var keys *pushKeys
			if !decodeStrict(value, &keys) || (keys == nil) != (sub.Keys == nil) ||
				keys != nil && *keys != *sub.Keys {
				return sub, invalidPush(name)
			}
		default:
			return sub, invalidPush(name)
		}
	}
	return sub, nil
}

func invalidPush(field string) object {
	return object{"type": "invalidProperties", "properties": []string{field}}
}

func validPushTypes(types []string) bool {
	if len(types) > 32 {
		return false
	}
	for _, kind := range types {
		if !jmapID.MatchString(kind) {
			return false
		}
	}
	return true
}

func pushExpiration(date *string, now time.Time) (time.Time, bool) {
	maximum := now.UTC().Add(maxPushAge).Truncate(time.Second)
	if date == nil {
		return maximum, true
	}
	expires, valid := vacationDate(*date)
	if expires.After(maximum) {
		expires = maximum
	}
	return expires, valid && expires.After(now)
}
