package gateway

import (
	"encoding/json"
	"mime"
	"net/textproto"
	"slices"
	"strings"
)

var partHeaderProperties = map[string][]string{
	"content-type":        {"type", "charset"},
	"content-disposition": {"disposition", "name"},
	"content-id":          {"cid"},
	"content-language":    {"language"},
	"content-location":    {"location"},
}

func decodeDraftPart(raw json.RawMessage) (draftPart, []draftHeader, bool) {
	var fields rawObject
	if !decodeStrict(raw, &fields) || fields == nil {
		return draftPart{}, nil, false
	}
	selectors, valid := compileHeaderProjections(sortedKeys(fields))
	if !valid {
		return draftPart{}, nil, false
	}

	var headers []draftHeader
	claimed := make(map[string]bool)
	for _, p := range selectors {
		if claimed[p.name] || p.name == "content-transfer-encoding" {
			return draftPart{}, nil, false
		}
		claimed[p.name] = true
		aliases := partHeaderProperties[p.name]
		for _, name := range aliases {
			if fields[name] != nil {
				return draftPart{}, nil, false
			}
		}
		values, valid := draftHeaderValues(p, fields[p.property])
		if !valid || len(aliases) != 0 && (len(values) > 1 || p.form != "asRaw") {
			return draftPart{}, nil, false
		}
		headers = append(headers, values...)
		delete(fields, p.property)
	}
	var part draftPart
	if !decodeArgs(fields, &part) {
		return draftPart{}, nil, false
	}
	return part, headers, true
}

func partHeader(headers []draftHeader, name string) (int, string) {
	for i, header := range headers {
		if header.name == name {
			return i, header.value
		}
	}
	return -1, ""
}

func draftPartType(part draftPart, fallback string, headers []draftHeader) (string, map[string]string, bool) {
	if index, wire := partHeader(headers, "content-type"); index >= 0 {
		kind, params, err := mime.ParseMediaType(strings.TrimSpace(unfoldDraftHeader(wire)))
		return kind, params, err == nil
	}
	kind := part.Type
	if kind == "" {
		kind = fallback
	}
	mediaType, params, err := mime.ParseMediaType(kind)
	return mediaType, params, err == nil && len(kind) <= 512 && len(params) == 0
}

func partTypeHeader(headers textproto.MIMEHeader, extra []draftHeader, kind string, params map[string]string, regenerate bool) []draftHeader {
	index, _ := partHeader(extra, "content-type")
	if index < 0 || regenerate {
		headers.Set("Content-Type", mime.FormatMediaType(kind, params))
		if index >= 0 {
			extra = slices.Delete(extra, index, index+1)
		}
	}
	return extra
}
