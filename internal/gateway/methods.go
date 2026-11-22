package gateway

import (
	"encoding/json"
	"strings"
	"time"
)

type accountArgs struct {
	AccountID string `json:"accountId"`
}

type getArgs struct {
	accountArgs
	IDs                 []string `json:"ids"`
	Properties          []string `json:"properties"`
	BodyProperties      []string `json:"bodyProperties"`
	FetchTextBodyValues bool     `json:"fetchTextBodyValues"`
	FetchHTMLBodyValues bool     `json:"fetchHTMLBodyValues"`
	FetchAllBodyValues  bool     `json:"fetchAllBodyValues"`
	MaxBodyValueBytes   int      `json:"maxBodyValueBytes"`
	headerFields        []headerProjection
	bodyHeaderFields    []headerProjection
}

type queryArgs struct {
	accountArgs
	queryDefinition
	Position       int64  `json:"position"`
	Anchor         string `json:"anchor"`
	AnchorOffset   int64  `json:"anchorOffset"`
	Limit          *int64 `json:"limit"`
	CalculateTotal bool   `json:"calculateTotal"`
}

type querySort struct {
	Property    string  `json:"property"`
	IsAscending *bool   `json:"isAscending"`
	Collation   string  `json:"collation"`
	Keyword     *string `json:"keyword"`
}

type setArgs struct {
	accountArgs
	IfInState             *string              `json:"ifInState"`
	Create                rawObject            `json:"create"`
	Update                rawObject            `json:"update"`
	Destroy               []string             `json:"destroy"`
	OnSuccessUpdateEmail  map[string]rawObject `json:"onSuccessUpdateEmail"`
	OnSuccessDestroyEmail []string             `json:"onSuccessDestroyEmail"`
}

func methodCapability(method string) string {
	switch strings.SplitN(method, "/", 2)[0] {
	case "Core", "Blob", "PushSubscription":
		return core
	case "Email", "Mailbox", "Thread", "SearchSnippet":
		return mailCapability
	case "EmailSubmission", "Identity":
		return submissionCapability
	case "Calendar":
		return calendarPreview
	case "VacationResponse":
		return vacationCapability
	default:
		return ""
	}
}

func (op *operation) call(call invocation) (string, object) {
	if call.name == "Core/echo" {
		result := make(object)
		for key, value := range call.args {
			result[key] = value
		}
		return call.name, result
	}
	if call.name == "PushSubscription/get" || call.name == "PushSubscription/set" {
		result, failure := op.pushMethod(call.name, call.args)
		if failure != "" {
			return methodError(failure)
		}
		return call.name, result
	}
	var accountID string
	switch call.name {
	case "Mailbox/get", "Mailbox/query", "Mailbox/set", "Email/get", "Email/query", "Email/set", "Email/import", "Email/parse", "Identity/get", "EmailSubmission/set", "EmailSubmission/get",
		"Thread/get", "Mailbox/changes", "Email/changes", "Thread/changes", "Identity/changes", "EmailSubmission/changes",
		"EmailSubmission/query", "Mailbox/queryChanges", "Email/queryChanges", "EmailSubmission/queryChanges", "SearchSnippet/get",
		"VacationResponse/get", "VacationResponse/set", "Blob/copy", "Email/copy", "Identity/set", "Calendar/get", "Calendar/changes":
		if json.Unmarshal(call.args["accountId"], &accountID) != nil || accountID == "" {
			return methodError("invalidArguments")
		}
	default:
		return methodError("unknownMethod")
	}
	target := op.forAccount(accountID)
	if target == nil {
		return methodError("accountNotFound")
	}
	if capability := methodCapability(call.name); capability == vacationCapability && target.g.sieveTLS == nil ||
		capability == calendarPreview && target.g.caldav == nil {
		return methodError("accountNotSupportedByMethod")
	}
	if root := op.requestOperation(); target != root {
		defer func() {
			root.implicit = target.implicit
			target.implicit = nil
		}()
	}
	op = target
	var result object
	var failure string
	switch call.name {
	case "Email/query":
		result, failure = op.query(call.args)
	case "Mailbox/query":
		result, failure = op.queryMailboxes(call.args)
	case "Mailbox/set":
		result, failure = op.setMailboxes(call.args)
	case "EmailSubmission/query":
		result, failure = op.executeQuery("EmailSubmission", call.args)
	case "Mailbox/queryChanges", "Email/queryChanges", "EmailSubmission/queryChanges":
		result, failure = op.queryChanges(strings.TrimSuffix(call.name, "/queryChanges"), call.args)
	case "Email/import":
		result, failure = op.importEmails(call.args)
	case "Blob/copy":
		result, failure = op.copyBlobs(call.args)
	case "Email/copy":
		result, failure = op.copyEmails(call.args)
	case "Email/parse":
		result, failure = op.parseEmails(call.args)
	case "SearchSnippet/get":
		result, failure = op.searchSnippets(call.args)
	case "Mailbox/changes", "Email/changes", "Thread/changes", "Identity/changes", "EmailSubmission/changes", "Calendar/changes":
		result, failure = op.changes(strings.TrimSuffix(call.name, "/changes"), call.args)
	case "Email/set", "EmailSubmission/set":
		result, failure = op.set(strings.TrimSuffix(call.name, "/set"), call.args)
	case "Identity/set":
		result, failure = op.setIdentities(call.args)
	case "VacationResponse/get":
		result, failure = op.getVacation(call.args)
	case "VacationResponse/set":
		result, failure = op.setVacation(call.args)
	default:
		result, failure = op.get(strings.TrimSuffix(call.name, "/get"), call.args)
	}
	if failure != "" {
		return methodError(failure)
	}
	result["accountId"] = accountID
	return call.name, result
}

func (op *operation) resolveID(id string) string {
	return resolveCreationID(id, op.created)
}

func resolveCreationID(id string, created map[string]string) string {
	if key, reference := strings.CutPrefix(id, "#"); reference {
		return created[key]
	}
	return id
}

func mailboxRecord(b *box) object {
	return object{
		"id": b.ID, "name": b.Name, "parentId": nullable(b.ParentID), "role": nullable(b.Role),
		"sortOrder": b.SortOrder, "isSubscribed": b.Subscribed,
		"totalEmails": b.Total, "unreadEmails": b.Unread, "totalThreads": b.TotalThreads, "unreadThreads": b.UnreadThreads,
		"myRights": b.mailboxRights(),
	}
}

func submissionObject(entry submissionRecord) object {
	recipients := make([]object, 0, len(entry.recipients()))
	for _, recipient := range entry.recipients() {
		recipients = append(recipients, object{"email": recipient, "parameters": nil})
	}
	return object{
		"id": entry.ID, "emailId": entry.EmailID, "threadId": threadID(entry.EmailID, entry.ThreadID),
		"identityId": entry.IdentityID, "sendAt": entry.SendAt.UTC().Format(time.RFC3339),
		"envelope": object{
			"mailFrom": object{"email": entry.From, "parameters": nil},
			"rcptTo":   recipients,
		}, "undoStatus": "final", "deliveryStatus": nil, "dsnBlobIds": []string{}, "mdnBlobIds": []string{},
	}
}

func (op *operation) submissions() map[string]submissionRecord {
	entries := make(map[string]submissionRecord)
	for _, entry := range op.g.ledger.records {
		if entry.Status == "accepted" {
			entries[entry.ID] = entry
		}
	}
	return entries
}

func (op *operation) get(kind string, raw rawObject) (object, string) {
	var a getArgs
	if !validGetArgumentNames(raw, kind) || !decodeArgs(raw, &a) ||
		a.MaxBodyValueBytes < 0 || int64(a.MaxBodyValueBytes) > maxJMAPInt {
		return nil, "invalidArguments"
	}
	if kind == "Email" && a.Properties == nil {
		a.Properties = defaultEmailProperties
	}
	if !validGetProperties(kind, &a) {
		return nil, "invalidArguments"
	}
	if failure := validateGetIDs(a.IDs); failure != "" {
		return nil, failure
	}
	if kind == "Mailbox" || kind == "Email" || kind == "Thread" {
		if failure := op.loadMail(); failure != "" {
			return nil, failure
		}
	}
	if kind == "Calendar" {
		if failure := op.loadCalendars(); failure != "" {
			return nil, failure
		}
	}
	records := make(map[string]object)
	state := op.state(kind)
	switch kind {
	case "Calendar":
		records = op.calendars
	case "Identity":
		records = op.g.identityRecords()
	case "Mailbox":
		for _, b := range op.snapshot.boxes {
			records[b.ID] = mailboxRecord(b)
		}
	case "EmailSubmission":
		for id, entry := range op.submissions() {
			records[id] = submissionObject(entry)
		}
	case "Thread":
		threads := op.snapshot.threads()
		if a.IDs == nil && len(threads) > maxGet {
			return nil, "requestTooLarge"
		}
		for id, members := range threads {
			records[id] = object{"id": id, "emailIds": members}
		}
	case "Email":
		if a.IDs == nil {
			if len(op.snapshot.emails) > maxGet {
				return nil, "requestTooLarge"
			}
			a.IDs = sortedKeys(op.snapshot.emails)
		}
	}
	ids := a.IDs
	if ids == nil {
		if len(records) > maxGet {
			return nil, "requestTooLarge"
		}
		ids = sortedKeys(records)
	}
	list := make([]object, 0, len(ids))
	notFound := make([]string, 0)
	for _, lookup := range op.uniqueGetIDs(ids) {
		id := lookup.resolved
		record := records[id]
		if kind == "Email" {
			if email := op.snapshot.emails[id]; email != nil {
				if metaOnly(a.Properties) {
					list = append(list, project(email.fields(), a.Properties))
					continue
				}
				var failure string
				record, failure = op.fetchEmailRecord(email, a)
				switch failure {
				case "", "notFound":
				default:
					return nil, failure
				}
			}
		}
		if record == nil {
			notFound = append(notFound, lookup.requested)
		} else {
			list = append(list, project(record, a.Properties))
		}
	}
	return object{"state": state, "list": list, "notFound": notFound}, ""
}

func (op *operation) fetchEmailRecord(email *emailMeta, args getArgs) (object, string) {
	if len(args.headerFields) > 0 && headerProjectionOnly(args.Properties) {
		header, failure := op.readEmailHeaders(email)
		if failure != "" {
			return nil, failure
		}
		record := email.fields()
		headers := rawHeaders(header.Fields())
		record["headers"] = headers
		renderHeaderProjections(record, headers, args.headerFields)
		return record, ""
	}
	body, failure := op.readRaw(email)
	if failure != "" {
		return nil, failure
	}
	message, failure := parseMIME(body, email.ID)
	if failure != "" {
		return nil, failure
	}
	return message.emailRecord(email, args), ""
}

func (op *operation) query(raw rawObject) (object, string) {
	return op.executeQuery("Email", raw)
}

func (op *operation) queryWindow(ids []string, a queryArgs, state string) (object, string) {
	position := a.Position
	if a.Anchor != "" {
		position = -1
		for index, id := range ids {
			if id == op.resolveID(a.Anchor) {
				position = int64(index)
				break
			}
		}
		if position < 0 {
			return nil, "anchorNotFound"
		}
		position += a.AnchorOffset
	} else if position < 0 {
		position += int64(len(ids))
	}
	position = max(position, 0)
	start := int(min(position, int64(len(ids))))
	limit := maxGet
	if a.Limit != nil {
		limit = int(min(*a.Limit, int64(limit)))
	}
	result := object{
		"queryState": state, "canCalculateChanges": true, "position": position,
		"ids": ids[start:min(start+limit, len(ids))],
	}
	if a.CalculateTotal {
		result["total"] = len(ids)
	}
	if a.Limit == nil || *a.Limit > int64(limit) {
		result["limit"] = limit
	}
	return result, ""
}

func (op *operation) set(kind string, raw rawObject) (object, string) {
	var a setArgs
	if !decodeArgs(raw, &a) {
		return nil, "invalidArguments"
	}
	if !validEmailActions(kind, a) {
		return nil, "invalidArguments"
	}
	if len(a.Create)+len(a.Update)+len(a.Destroy) > maxSet ||
		len(a.OnSuccessUpdateEmail)+len(a.OnSuccessDestroyEmail) > maxSet {
		return nil, "requestTooLarge"
	}
	for key := range a.Create {
		if !jmapID.MatchString(key) {
			return nil, "invalidArguments"
		}
	}
	if kind == "Email" {
		if failure := op.loadMail(); failure != "" {
			return nil, failure
		}
	}
	oldState := op.state(kind)
	if a.IfInState != nil && *a.IfInState != oldState {
		return nil, "stateMismatch"
	}

	created, updated, notCreated, notUpdated, notDestroyed := object{}, object{}, object{}, object{}, object{}
	for _, key := range sortedKeys(a.Create) {
		id, failure := "", object(nil)
		if kind == "Email" {
			id, failure = op.createDraft(a.Create[key])
		} else {
			id, failure = op.submit(a.Create[key])
		}
		if failure != nil {
			notCreated[key] = failure
		} else {
			op.created[key] = id
			created[key] = object{"id": id}
			if kind == "Email" {
				created[key] = createdEmail(op.snapshot.emails[id])
			}
		}
	}
	var submissions map[string]submissionRecord
	successfulSubmissions := make(map[string]string)
	if kind == "EmailSubmission" {
		submissions = op.submissions()
		for key := range created {
			entry := submissions[op.created[key]]
			created[key] = createdSubmission(entry, a.Create[key])
			successfulSubmissions[entry.ID] = entry.EmailID
		}
	}
	for _, key := range sortedKeys(a.Update) {
		id := op.resolveID(key)
		var failure object
		switch {
		case kind == "EmailSubmission":
			entry := submissions[id]
			failure = updateSubmission(entry, a.Update[key])
			if failure == nil {
				successfulSubmissions[id] = entry.EmailID
			}
		case op.snapshotFailure != "":
			failure = object{"type": op.snapshotFailure}
		default:
			failure = op.updateEmail(id, a.Update[key])
		}
		if failure == nil {
			updated[id] = nil
		} else {
			notUpdated[key] = failure
		}
	}
	var destroyed []string
	for _, key := range a.Destroy {
		id := op.resolveID(key)
		failure := op.snapshotFailure
		if kind == "EmailSubmission" {
			entry := submissions[id]
			failure = op.g.ledger.destroySubmission(id)
			if failure == "" {
				successfulSubmissions[id] = entry.EmailID
			}
		} else if failure == "" {
			failure = op.destroyEmail(id)
		}
		if failure == "" {
			destroyed = append(destroyed, id)
		} else {
			notDestroyed[key] = object{"type": failure}
		}
	}
	if kind == "EmailSubmission" && (len(a.OnSuccessUpdateEmail) > 0 || len(a.OnSuccessDestroyEmail) > 0) {
		op.applySubmissionEmailActions(a, successfulSubmissions)
	}
	return object{"oldState": oldState, "newState": op.state(kind), "created": optionalSetMap(created),
		"updated": optionalSetMap(updated), "destroyed": destroyed, "notCreated": optionalSetMap(notCreated),
		"notUpdated": optionalSetMap(notUpdated), "notDestroyed": optionalSetMap(notDestroyed)}, ""
}

func (op *operation) createDraft(input json.RawMessage) (string, object) {
	if len(op.snapshot.emails) >= maxMessages {
		return "", object{"type": "overQuota"}
	}
	now := time.Now().UTC().Truncate(time.Second)
	draft, failure := makeDraft(input, now, op.g.allowsIdentity, op.readDraftBlob)
	if failure != nil {
		return "", failure
	}
	if len(draft.mailboxIDs) > 1 {
		return "", object{"type": "tooManyMailboxes"}
	}
	var folder *box
	for id, enabled := range draft.mailboxIDs {
		if enabled {
			folder = op.snapshot.mailbox(op.resolveID(id))
		}
	}
	if folder == nil {
		return "", invalidProperty("mailboxIds")
	}
	flags, valid := importFlags(draft.keywords)
	if !valid {
		return "", invalidProperty("keywords")
	}
	added, status := appendEmail(op.client, folder, draft.raw, flags, now)
	if status != "" {
		return "", object{"type": status}
	}
	added.ThreadID = threadForMessage(op.g.config.AccountID, draft.raw)
	op.snapshot.recordAppend(folder, added)
	return added.ID, nil
}

func (op *operation) readDraftBlob(id string) ([]byte, string) {
	location, valid := locateBlob(op.resolveID(id))
	if !valid {
		return nil, "notFound"
	}
	return op.readBlob(location)
}

func (s *snapshot) recordAppend(mailbox *box, added *emailMeta) {
	for id, email := range s.emails {
		if email.MailboxID == mailbox.ID && email.Validity != added.Validity {
			delete(s.emails, id)
		}
	}
	s.emails[added.ID] = added
	s.countMailboxes()
}

func createdEmail(email *emailMeta) object {
	return object{
		"id": email.ID, "blobId": "b-" + email.ID[2:], "threadId": threadID(email.ID, email.ThreadID), "size": email.Size,
	}
}

func (op *operation) submit(raw json.RawMessage) (string, object) {
	fail := func(code string, details string) (string, object) {
		result := object{"type": code}
		if details != "" {
			result["description"] = details
		}
		return "", result
	}
	var input struct {
		EmailID    string        `json:"emailId"`
		IdentityID string        `json:"identityId"`
		Envelope   *smtpEnvelope `json:"envelope"`
	}
	if !decodeStrict(raw, &input) {
		return fail("invalidProperties", "")
	}
	selectedID := op.resolveID(input.IdentityID)
	identity, found := op.g.identity(selectedID)
	if !found {
		return "", invalidProperty("identityId")
	}
	var explicit []string
	if input.Envelope != nil {
		var failure object
		explicit, failure = input.Envelope.recipients(identity.Email)
		if failure != nil {
			return "", failure
		}
	}
	id := op.resolveID(input.EmailID)
	if !strings.HasPrefix(id, "e-") || len(id) != 45 {
		return "", object{"type": "invalidProperties", "properties": []string{"emailId"}}
	}
	l := op.g.ledger
	if l.failed {
		return fail("serverFail", "Submission ledger requires operator recovery")
	}
	for _, previous := range l.records {
		if previous.EmailID == id {
			return replaySubmission(previous, selectedID, explicit)
		}
	}
	if failure := op.loadMail(); failure != "" {
		return fail(failure, "")
	}
	email := op.snapshot.emails[id]
	if email == nil {
		return "", object{"type": "invalidProperties", "properties": []string{"emailId"}}
	}
	if email.Size > maxRaw {
		return "", object{"type": "tooLarge", "maxSize": maxRaw}
	}
	body, failure := op.readRaw(email)
	if failure == "notFound" {
		return "", object{"type": "invalidProperties", "properties": []string{"emailId"}}
	}
	if failure != "" {
		return fail(failure, "")
	}
	prepared, envelopeFailure := prepareSubmission(body, identity.Email, explicit)
	if envelopeFailure != nil {
		return "", envelopeFailure
	}
	for _, key := range []string{prepared.key, prepared.legacyKey} {
		if previous, ok := l.records[key]; ok {
			return replaySubmission(previous, selectedID, explicit)
		}
	}
	entry := submissionRecord{ID: "s-" + randomID(), EmailID: id, ThreadID: email.ThreadID, IdentityID: selectedID,
		From: identity.Email, Recipients: prepared.recipients, SendAt: time.Now().UTC(), Status: "pending"}
	l.records[prepared.key] = entry
	if l.save() != nil {
		return fail("serverFail", "Submission could not be reserved")
	}
	outcome := sendSMTP(op.ctx, op.g.config.SMTP, op.g.smtpTLS, entry.From, prepared.recipients, prepared.wire, prepared.transport)
	if outcome.uncertain {
		return fail("serverFail", "SMTP acceptance is unknown. This message is blocked from resubmission")
	}
	if outcome.failure != "" {
		delete(l.records, prepared.key)
		if l.save() != nil {
			return fail("serverFail", "Submission ledger requires operator recovery")
		}
		if outcome.failure == "invalidRecipients" {
			return "", object{"type": "invalidRecipients", "invalidRecipients": outcome.rejected}
		}
		if outcome.failure == "tooLarge" {
			return "", object{"type": "tooLarge", "maxSize": outcome.maxSize}
		}
		return fail(outcome.failure, outcome.description)
	}
	entry.Status = "accepted"
	l.records[prepared.key] = entry
	if l.save() != nil {
		return fail("serverFail", "SMTP accepted the message. Submission ledger requires operator recovery")
	}
	return entry.ID, nil
}
