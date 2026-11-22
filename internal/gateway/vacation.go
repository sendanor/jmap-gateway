package gateway

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"
)

const (
	vacationID       = "singleton"
	vacationMetadata = "# jmap-vacation-1 "
	maxVacationBody  = 12 << 10
	sieveUTC         = "2006-01-02T15:04:05+00:00"
)

type vacationResponse struct {
	Enabled  bool    `json:"isEnabled"`
	FromDate *string `json:"fromDate"`
	ToDate   *string `json:"toDate"`
	Subject  *string `json:"subject"`
	TextBody *string `json:"textBody"`
	HTMLBody *string `json:"htmlBody"`
}

func (v vacationResponse) record() object {
	return object{"id": vacationID, "isEnabled": v.Enabled, "fromDate": v.FromDate, "toDate": v.ToDate,
		"subject": v.Subject, "textBody": v.TextBody, "htmlBody": v.HTMLBody}
}

func vacationDate(raw string) (time.Time, bool) {
	date, err := time.Parse(time.RFC3339, raw)
	return date, err == nil && raw == date.UTC().Format(time.RFC3339)
}

func (v vacationResponse) invalidProperties() []string {
	var invalid []string
	from, to := time.Time{}, time.Time{}
	if v.FromDate != nil {
		date, ok := vacationDate(*v.FromDate)
		if !ok {
			invalid = append(invalid, "fromDate")
		}
		from = date
	}
	if v.ToDate != nil {
		date, ok := vacationDate(*v.ToDate)
		if !ok {
			invalid = append(invalid, "toDate")
		}
		to = date
	}
	if len(invalid) == 0 && v.FromDate != nil && v.ToDate != nil && !from.Before(to) {
		invalid = []string{"fromDate", "toDate"}
	}
	if v.Subject != nil && !safeDraftHeader(*v.Subject, 200) {
		invalid = append(invalid, "subject")
	}
	for _, body := range []struct {
		name  string
		value *string
	}{{"textBody", v.TextBody}, {"htmlBody", v.HTMLBody}} {
		if body.value != nil && (len(*body.value) > maxVacationBody ||
			strings.IndexFunc(*body.value, func(r rune) bool {
				return unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t'
			}) >= 0) {
			invalid = append(invalid, body.name)
		}
	}
	return invalid
}

func (v vacationResponse) updated(raw json.RawMessage) (vacationResponse, object) {
	var patch rawObject
	if !decodeStrict(raw, &patch) || patch == nil {
		return vacationResponse{}, object{"type": "invalidPatch"}
	}
	fields := map[string]**string{"fromDate": &v.FromDate, "toDate": &v.ToDate,
		"subject": &v.Subject, "textBody": &v.TextBody, "htmlBody": &v.HTMLBody}
	var invalid []string
	for _, key := range sortedKeys(patch) {
		value := patch[key]
		switch key {
		case "id":
			var id string
			if !decodeStrict(value, &id) || id != vacationID {
				invalid = append(invalid, key)
			}
		case "isEnabled":
			var enabled *bool
			if !decodeStrict(value, &enabled) || enabled == nil {
				invalid = append(invalid, key)
			} else {
				v.Enabled = *enabled
			}
		default:
			var text *string
			if field := fields[key]; field == nil || !decodeStrict(value, &text) {
				invalid = append(invalid, key)
			} else {
				*field = text
			}
		}
	}
	invalid = append(invalid, v.invalidProperties()...)
	if len(invalid) != 0 {
		return vacationResponse{}, object{"type": "invalidProperties", "properties": invalid}
	}
	return v, nil
}

func (op *operation) getVacation(raw rawObject) (object, string) {
	var args struct {
		accountArgs
		IDs        []string `json:"ids"`
		Properties []string `json:"properties"`
	}
	if !validGetArgumentNames(raw, "VacationResponse") || !decodeArgs(raw, &args) {
		return nil, "invalidArguments"
	}
	if failure := validateGetIDs(args.IDs); failure != "" {
		return nil, failure
	}
	if !validRecordProperties(args.Properties, (vacationResponse{}).record()) {
		return nil, "invalidArguments"
	}
	client, closeClient, failure := op.vacationClient()
	if failure != "" {
		return nil, failure
	}
	defer closeClient()
	settings, failure := client.getVacation()
	if failure != "" {
		return nil, failure
	}
	list, notFound := []object{}, []string{}
	if args.IDs == nil {
		args.IDs = []string{vacationID}
	}
	for _, lookup := range op.uniqueGetIDs(args.IDs) {
		if lookup.resolved == vacationID {
			list = append(list, project(settings.record(), args.Properties))
		} else {
			notFound = append(notFound, lookup.requested)
		}
	}
	return object{"state": digest(settings), "list": list, "notFound": notFound}, ""
}

func (op *operation) setVacation(raw rawObject) (object, string) {
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
	client, closeClient, failure := op.vacationClient()
	if failure != "" {
		return nil, failure
	}
	defer closeClient()
	settings, failure := client.getVacation()
	if failure != "" {
		return nil, failure
	}
	oldState := digest(settings)
	if args.IfInState != nil && *args.IfInState != oldState {
		return nil, "stateMismatch"
	}
	updated, notCreated, notUpdated, notDestroyed := object{}, object{}, object{}, object{}
	for key := range args.Create {
		notCreated[key] = object{"type": "singleton"}
	}
	for _, key := range sortedKeys(args.Update) {
		if op.resolveID(key) != vacationID {
			notUpdated[key] = object{"type": "notFound"}
			continue
		}
		next, invalid := settings.updated(args.Update[key])
		if invalid != nil {
			notUpdated[key] = invalid
			continue
		}
		if digest(next) != digest(settings) {
			if failure := client.putVacation(next.script(op.g.config.IdentityEmail)); failure != "" {
				return nil, failure
			}
			settings = next
		}
		updated[vacationID] = nil
	}
	for _, key := range args.Destroy {
		kind := "singleton"
		if op.resolveID(key) != vacationID {
			kind = "notFound"
		}
		notDestroyed[key] = object{"type": kind}
	}
	return object{"oldState": oldState, "newState": digest(settings), "created": nil, "destroyed": nil,
		"updated": optionalSetMap(updated), "notCreated": optionalSetMap(notCreated), "notUpdated": optionalSetMap(notUpdated),
		"notDestroyed": optionalSetMap(notDestroyed)}, ""
}

func decodeVacationScript(script []byte, out *vacationResponse) bool {
	meta, code, found := bytes.Cut(script, []byte("\r\n"))
	fields, owned := bytes.CutPrefix(meta, []byte(vacationMetadata))
	checksum, encoded, split := bytes.Cut(fields, []byte(" "))
	if !found || !owned || !split || string(checksum) != digest(string(encoded)+"\n"+string(code)) {
		return false
	}
	value, err := base64.RawStdEncoding.DecodeString(string(encoded))
	return err == nil && decodeStrict(value, out) && len(out.invalidProperties()) == 0
}

func sieveQuoted(value string) string {
	return "\"" + strings.NewReplacer("\\", "\\\\", "\"", "\\\"").Replace(value) + "\""
}

func (v vacationResponse) script(identity string) []byte {
	var settings bytes.Buffer
	encoder := json.NewEncoder(&settings)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(v)
	code := v.sieveCode(identity)
	encoded := base64.RawStdEncoding.EncodeToString(settings.Bytes())
	header := fmt.Appendf(nil, "%s%s %s\r\n", vacationMetadata, digest(encoded+"\n"+string(code)), encoded)
	return append(header, code...)
}

func (v vacationResponse) sieveCode(identity string) []byte {
	var script bytes.Buffer
	if !v.Enabled {
		return script.Bytes()
	}
	script.WriteString("require [\"vacation\", \"date\", \"relational\"];\r\n")
	var dates []string
	for _, bound := range []struct {
		op   string
		date *string
	}{{"ge", v.FromDate}, {"lt", v.ToDate}} {
		if bound.date != nil {
			date, _ := vacationDate(*bound.date)
			dates = append(dates, fmt.Sprintf("currentdate :zone \"+0000\" :value %q \"iso8601\" %q", bound.op, date.Format(sieveUTC)))
		}
	}
	if len(dates) != 0 {
		fmt.Fprintf(&script, "if allof (%s) {\r\n", strings.Join(dates, ", "))
	}
	fmt.Fprintf(&script, "vacation :days 7 :handle \"jmap-vacation\" :addresses [%s] :from %s",
		sieveQuoted(identity), sieveQuoted(identity))
	if v.Subject != nil {
		fmt.Fprintf(&script, " :subject %s", sieveQuoted(*v.Subject))
	}
	script.WriteString(" :mime text:\r\n")
	for _, line := range strings.Split(v.mimeBody(), "\r\n") {
		if strings.HasPrefix(line, ".") {
			script.WriteByte('.')
		}
		script.WriteString(line)
		script.WriteString("\r\n")
	}
	script.WriteString(".\r\n;\r\n")
	if len(dates) != 0 {
		script.WriteString("}\r\n")
	}
	return script.Bytes()
}

func (v vacationResponse) mimeBody() string {
	plain := v.TextBody
	if plain == nil && v.HTMLBody == nil {
		message := "I am currently away and will reply when I return."
		plain = &message
	}
	var parts []encodedDraftPart
	for _, body := range []struct {
		mediaType string
		value     *string
	}{{"text/plain", plain}, {"text/html", v.HTMLBody}} {
		if body.value != nil {
			part := encodedDraftPart{headers: map[string][]string{}, body: draftQuotedPrintable(*body.value)}
			part.headers.Set("Content-Type", body.mediaType+"; charset=utf-8")
			part.headers.Set("Content-Transfer-Encoding", "quoted-printable")
			parts = append(parts, part)
		}
	}
	part := parts[0]
	if len(parts) > 1 {
		part = combineDraftParts("multipart/alternative", nil, nil, nil, parts)
	}
	var mime bytes.Buffer
	for _, key := range sortedKeys(part.headers) {
		fmt.Fprintf(&mime, "%s: %s\r\n", key, part.headers.Get(key))
	}
	mime.WriteString("\r\n")
	mime.Write(part.body)
	return strings.TrimSuffix(mime.String(), "\r\n")
}
