package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
)

const (
	core                 = "urn:ietf:params:jmap:core"
	mailCapability       = "urn:ietf:params:jmap:mail"
	submissionCapability = "urn:ietf:params:jmap:submission"
	vacationCapability   = "urn:ietf:params:jmap:vacationresponse"
	maxRequest           = 1 << 20
	maxCalls             = 32
	maxGet               = 32
	maxSet               = 16
	maxConcurrent        = 4
)

type Gateway struct {
	unflushedMoves   *emailMoveState
	uploads          blobStore
	history          changeHistory
	queries          queryHistory
	config           Config
	imapTLS, smtpTLS *tls.Config
	sieveTLS         *tls.Config
	caldav           *calDAV
	ledger           *ledger
	auth             [32]byte
	admitted         chan struct{}
	gate             chan struct{}
	session          object
	sessionState     string
	eventSlots       chan struct{}
	eventsDone       chan struct{}
	stopEvents       sync.Once
	eventCache       eventObservation
	push             *pushStore
	accounts         map[string]*Gateway
	identities       map[string]identityProfile
}

func newAccount(config Config) (*Gateway, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	imapTLS, err := upstreamTLS(config.IMAP)
	if err != nil {
		return nil, err
	}
	smtpTLS, err := upstreamTLS(config.SMTP)
	if err != nil {
		return nil, err
	}
	var sieveTLS *tls.Config
	if config.ManageSieve != nil {
		sieveTLS, err = upstreamTLS(*config.ManageSieve)
		if err != nil {
			return nil, err
		}
	}
	dav, err := newCalDAV(config.CalDAV)
	if err != nil {
		return nil, err
	}
	ledger, err := openLedger(config.StateDir, config.AccountID)
	if err != nil {
		return nil, err
	}
	history, err := openChangeHistory(config.StateDir, localAtomicFiles)
	if err != nil {
		_ = ledger.lock.Close()
		return nil, err
	}
	g := &Gateway{
		config: config, imapTLS: imapTLS, smtpTLS: smtpTLS, sieveTLS: sieveTLS, caldav: dav, ledger: ledger,
		uploads: blobStore{dir: config.StateDir, quota: unreferencedBlobQuota, files: localAtomicFiles},
		history: history,
		queries: queryHistory{dir: config.StateDir, files: localAtomicFiles},
		auth:    sha256.Sum256([]byte(config.Token)), admitted: make(chan struct{}, maxConcurrent),
		gate:       make(chan struct{}, 1),
		eventSlots: make(chan struct{}, maxEventStreams), eventsDone: make(chan struct{}),
	}
	g.config.Token = ""
	if err := g.loadIdentities(); err != nil {
		_ = ledger.lock.Close()
		return nil, err
	}
	account := config.AccountID
	base := config.PublicOrigin
	g.session = object{
		"capabilities": object{
			core: object{
				"maxSizeUpload": maxUploadBytes, "maxConcurrentUpload": maxConcurrentUploads,
				"maxSizeRequest": maxRequest, "maxConcurrentRequests": maxConcurrent,
				"maxCallsInRequest": maxCalls, "maxObjectsInGet": maxGet, "maxObjectsInSet": maxSet,
				"collationAlgorithms": queryCollationAlgorithms,
			},
			mailCapability: object{}, submissionCapability: object{},
		},
		"accounts": object{account: object{
			"name": config.IdentityEmail, "isPersonal": true, "isReadOnly": false,
			"accountCapabilities": object{
				mailCapability: object{
					"maxMailboxesPerEmail": 1, "maxMailboxDepth": nil,
					"maxSizeMailboxName": maxMailboxName, "maxSizeAttachmentsPerEmail": maxDraftAttachmentBytes,
					"emailQuerySortOptions": emailQuerySortOptions, "mayCreateTopLevelMailbox": true,
				},
				submissionCapability: object{"maxDelayedSend": 0, "submissionExtensions": object{}},
			},
		}},
		"primaryAccounts": object{mailCapability: account, submissionCapability: account},
		"username":        config.IdentityEmail, "apiUrl": base + "/jmap",
		"downloadUrl":    base + "/download/{accountId}/{blobId}/{name}?type={type}",
		"uploadUrl":      base + "/upload/{accountId}",
		"eventSourceUrl": base + "/events?types={types}&closeafter={closeafter}&ping={ping}",
	}
	if sieveTLS != nil {
		g.enableAccountCapability(account, vacationCapability)
	}
	if dav != nil {
		g.enableAccountCapability(account, calendarPreview)
	}
	return g, nil
}

func (g *Gateway) StopEvents() { g.stopEvents.Do(func() { close(g.eventsDone) }) }

func (g *Gateway) Close() error {
	g.StopEvents()
	if g.push != nil {
		g.push.stop()
	}
	var failure error
	for _, account := range g.accounts {
		failure = errors.Join(failure, account.ledger.lock.Close())
	}
	return errors.Join(failure, g.ledger.lock.Close())
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.TLS == nil {
		http.Error(w, "HTTPS required", http.StatusBadRequest)
		return
	}
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	candidate := sha256.Sum256([]byte(token))
	if !ok || !strings.EqualFold(scheme, "Bearer") || subtle.ConstantTimeCompare(candidate[:], g.auth[:]) != 1 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="JMAP"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	switch {
	case r.URL.Path == "/.well-known/jmap":
		if allowMethod(w, r, http.MethodGet) {
			writeJSON(w, http.StatusOK, g.session)
		}
	case r.URL.Path == "/jmap":
		if allowMethod(w, r, http.MethodPost) {
			g.serveAPI(w, r)
		}
	case strings.HasPrefix(r.URL.EscapedPath(), "/download/"):
		if allowMethod(w, r, http.MethodGet) {
			parts := strings.SplitN(r.URL.EscapedPath(), "/", 4)
			if account := g.account(parts[2]); account != nil {
				account.serveDownload(w, r)
			} else {
				http.NotFound(w, r)
			}
		}
	case strings.HasPrefix(r.URL.EscapedPath(), "/upload/"):
		if account := g.account(strings.TrimPrefix(r.URL.EscapedPath(), "/upload/")); account == nil {
			http.NotFound(w, r)
		} else if allowMethod(w, r, http.MethodPost) {
			account.serveUpload(w, r)
		}
	case r.URL.Path == "/events":
		if allowMethod(w, r, http.MethodGet) {
			g.serveEvents(w, r)
		}
	default:
		http.NotFound(w, r)
	}
}

func allowMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method == method {
		return true
	}
	w.Header().Set("Allow", method)
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	return false
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func problem(w http.ResponseWriter, status int, kind string, limit ...string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	details := object{"type": "urn:ietf:params:jmap:error:" + kind, "status": status}
	if len(limit) != 0 {
		details["limit"] = limit[0]
	}
	_ = json.NewEncoder(w).Encode(details)
}

type invocation struct {
	name string
	args rawObject
	id   string
}

type rawObject = map[string]json.RawMessage

func decodeStrict(data json.RawMessage, out any) bool {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(out) == nil && dec.Decode(new(any)) == io.EOF
}

func decodeArgs(args rawObject, out any) bool {
	data, _ := json.Marshal(args)
	return decodeStrict(data, out)
}

func (g *Gateway) serveAPI(w http.ResponseWriter, r *http.Request) {
	kind, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || kind != "application/json" {
		problem(w, http.StatusUnsupportedMediaType, "notJSON")
		return
	}
	defer r.Body.Close()
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequest))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			problem(w, http.StatusRequestEntityTooLarge, "limit", "maxSizeRequest")
		} else {
			problem(w, http.StatusBadRequest, "notJSON")
		}
		return
	}
	if !validIJSON(body) {
		problem(w, http.StatusBadRequest, "notJSON")
		return
	}
	var fields rawObject
	var using []*string
	var tuples [][]json.RawMessage
	if json.Unmarshal(body, &fields) != nil ||
		json.Unmarshal(fields["using"], &using) != nil || using == nil ||
		json.Unmarshal(fields["methodCalls"], &tuples) != nil || tuples == nil {
		problem(w, http.StatusBadRequest, "notRequest")
		return
	}
	var created map[string]string
	if raw := fields["createdIds"]; raw != nil && (json.Unmarshal(raw, &created) != nil || created == nil) {
		problem(w, http.StatusBadRequest, "notRequest")
		return
	}
	for _, capability := range using {
		if capability == nil {
			problem(w, http.StatusBadRequest, "notRequest")
			return
		}
	}
	capabilities := make(map[string]bool)
	for _, entry := range using {
		capability := *entry
		if _, available := g.session["capabilities"].(object)[capability]; !available {
			problem(w, http.StatusBadRequest, "unknownCapability")
			return
		}
		capabilities[capability] = true
	}
	if len(tuples) > maxCalls {
		problem(w, http.StatusRequestEntityTooLarge, "limit", "maxCallsInRequest")
		return
	}
	calls := make([]invocation, 0, len(tuples))
	for _, tuple := range tuples {
		var call invocation
		var name, id *string
		if len(tuple) != 3 || json.Unmarshal(tuple[0], &name) != nil || name == nil ||
			json.Unmarshal(tuple[1], &call.args) != nil || call.args == nil ||
			json.Unmarshal(tuple[2], &id) != nil || id == nil {
			problem(w, http.StatusBadRequest, "notRequest")
			return
		}
		call.name, call.id = *name, *id
		calls = append(calls, call)
	}
	for key, id := range created {
		if !jmapID.MatchString(key) || !jmapID.MatchString(id) {
			problem(w, http.StatusBadRequest, "notRequest")
			return
		}
	}
	op, end, ok := g.start(w, r)
	if !ok {
		return
	}
	defer end()
	op.created = created
	if op.created == nil {
		op.created = make(map[string]string)
	}
	responses := make([][3]any, 0, len(calls))
	resolved := make(map[string]invocationResult)
	for _, call := range calls {
		name, result := call.name, object(nil)
		if op.ctx.Err() != nil {
			name, result = methodError("serverUnavailable")
		} else if failure := resolveArgs(call.args, resolved); failure != "" {
			name, result = methodError(failure)
		} else if !capabilities[methodCapability(name)] {
			name, result = methodError("unknownMethod")
		} else {
			name, result = op.call(call)
		}
		responses = append(responses, [3]any{name, result, call.id})
		if _, seen := resolved[call.id]; !seen {
			resolved[call.id] = invocationResult{name, result}
		}
		if implicit := op.implicit; implicit != nil {
			responses = append(responses, [3]any{implicit.name, implicit.args, call.id})
			op.implicit = nil
		}
	}
	result := object{"methodResponses": responses, "sessionState": g.sessionState}
	if created != nil {
		result["createdIds"] = op.created
	}
	writeJSON(w, http.StatusOK, result)
}

type invocationResult struct {
	name string
	args object
}

func resolveArgs(args rawObject, resolved map[string]invocationResult) string {
	keys := sortedKeys(args)
	for _, key := range keys {
		if !strings.HasPrefix(key, "#") {
			continue
		}
		destination := key[1:]
		if args[destination] != nil {
			return "invalidArguments"
		}
	}
	var expandedSize int
	for _, key := range keys {
		if !strings.HasPrefix(key, "#") {
			continue
		}
		destination := key[1:]
		var ref rawObject
		if json.Unmarshal(args[key], &ref) != nil || len(ref) != 3 {
			return "invalidResultReference"
		}
		var resultOf, name, pointerPath *string
		if json.Unmarshal(ref["resultOf"], &resultOf) != nil || resultOf == nil ||
			json.Unmarshal(ref["name"], &name) != nil || name == nil ||
			json.Unmarshal(ref["path"], &pointerPath) != nil || pointerPath == nil {
			return "invalidResultReference"
		}
		result, exists := resolved[*resultOf]
		if !exists || result.name != *name {
			return "invalidResultReference"
		}
		serialized, _ := json.Marshal(result.args)
		var tree any
		decoder := json.NewDecoder(bytes.NewReader(serialized))
		decoder.UseNumber()
		if decoder.Decode(&tree) != nil {
			return "invalidResultReference"
		}
		var path []string
		if strings.HasPrefix(*pointerPath, "/") && validPointerEscapes(*pointerPath) {
			path = strings.Split((*pointerPath)[1:], "/")
		} else if *pointerPath != "" {
			return "invalidResultReference"
		}
		value, ok := pointer(tree, path)
		if !ok {
			return "invalidResultReference"
		}
		encoded, _ := json.Marshal(value) // The value was decoded from JSON above.
		expandedSize += len(encoded)
		if expandedSize > maxRequest {
			return "invalidResultReference"
		}
		args[destination] = encoded
		delete(args, key)
	}
	return ""
}

func validPointerEscapes(path string) bool {
	for i := 0; i < len(path); i++ {
		if path[i] == '~' {
			i++
			if i == len(path) || path[i] != '0' && path[i] != '1' {
				return false
			}
		}
	}
	return true
}

func unescapePointerToken(token string) string {
	return strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~")
}

func pointer(node any, path []string) (any, bool) {
	if len(path) == 0 {
		return node, true
	}
	key := unescapePointerToken(path[0])
	switch node := node.(type) {
	case map[string]any:
		child, ok := node[key]
		if ok {
			return pointer(child, path[1:])
		}
	case []any:
		if key == "*" {
			list := make([]any, 0)
			for _, child := range node {
				value, ok := pointer(child, path[1:])
				if !ok {
					return nil, false
				}
				if values, multiple := value.([]any); multiple {
					list = append(list, values...)
				} else {
					list = append(list, value)
				}
			}
			return list, true
		}
		i, err := strconv.Atoi(key)
		if err == nil && i >= 0 && i < len(node) && strconv.Itoa(i) == key {
			return pointer(node[i], path[1:])
		}
	}
	return nil, false
}

func (g *Gateway) start(w http.ResponseWriter, r *http.Request) (*operation, func(), bool) {
	select {
	case g.admitted <- struct{}{}:
	default:
		w.Header().Set("Retry-After", "1")
		problem(w, http.StatusServiceUnavailable, "limit", "maxConcurrentRequests")
		return nil, nil, false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 55*time.Second)
	select {
	case g.gate <- struct{}{}:
		op := &operation{g: g, ctx: ctx}
		return op, func() {
			op.closeConnections()
			cancel()
			<-g.gate
			<-g.admitted
		}, true
	case <-ctx.Done():
		cancel()
		<-g.admitted
		http.Error(w, "Request timed out", http.StatusServiceUnavailable)
		return nil, nil, false
	}
}

type operation struct {
	g               *Gateway
	ctx             context.Context
	client          *imapclient.Client
	closeIMAP       func()
	snapshot        *snapshot
	snapshotFailure string
	calendars       map[string]object
	calendarFailure string
	created         map[string]string
	rawBytes        int64
	implicit        *invocationResult
	parent          *operation
	peers           map[string]*operation
}

func (op *operation) loadMail() string {
	if op.snapshot != nil || op.snapshotFailure != "" {
		return op.snapshotFailure
	}
	client, closeClient, err := op.g.connectIMAP(op.ctx)
	if err != nil {
		op.snapshotFailure = "serverUnavailable"
		return op.snapshotFailure
	}
	op.client, op.closeIMAP = client, closeClient
	op.snapshot, op.snapshotFailure = op.g.scan(client)
	return op.snapshotFailure
}

func (op *operation) readRaw(email *emailMeta) ([]byte, string) {
	budget := op.requestOperation()
	if budget.rawBytes+email.Size > 12*maxRaw {
		return nil, "requestTooLarge"
	}
	raw, failure := fetchRaw(op.client, email)
	budget.rawBytes += int64(len(raw))
	return raw, failure
}

func (g *Gateway) serveDownload(w http.ResponseWriter, r *http.Request) {
	path := strings.Split(r.URL.EscapedPath(), "/")
	if len(path) != 5 || path[2] != g.config.AccountID || !jmapID.MatchString(path[3]) || len(path[3]) < 45 {
		http.NotFound(w, r)
		return
	}
	location, valid := locateBlob(path[3])
	if !valid {
		http.NotFound(w, r)
		return
	}
	op, end, ok := g.start(w, r)
	if !ok {
		return
	}
	defer end()
	raw, failure := op.readBlob(location)
	switch failure {
	case "notFound":
		http.NotFound(w, r)
	case "":
		writeDownload(w, r, path[4], raw)
	default:
		http.Error(w, "Blob unavailable", http.StatusServiceUnavailable)
	}
}

func writeDownload(w http.ResponseWriter, r *http.Request, escapedName string, data []byte) {
	kind := "application/octet-stream"
	if requested := r.URL.Query().Get("type"); requested != "" {
		if mediaType, params, err := mime.ParseMediaType(requested); err == nil && strings.Contains(mediaType, "/") {
			kind = mime.FormatMediaType(mediaType, params)
		}
	}
	name, _ := url.PathUnescape(escapedName)
	w.Header().Set("Content-Type", kind)
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	_, _ = w.Write(data)
}

func methodError(kind string) (string, object) { return "error", object{"type": kind} }

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func contains(items []string, item string) bool { return slices.Contains(items, item) }

func project(record object, properties []string) object {
	if properties == nil {
		return record
	}
	out := make(object)
	for key, value := range record {
		if key == "id" || contains(properties, key) {
			out[key] = value
		}
	}
	return out
}

func randomID() string {
	var id [16]byte
	_, _ = rand.Read(id[:])
	return hex.EncodeToString(id[:])
}
