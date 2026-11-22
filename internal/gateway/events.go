package gateway

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	maxEventStreams   = 4
	eventPollInterval = 2 * time.Second
	eventPollTimeout  = 5 * time.Second
	eventWriteTimeout = 5 * time.Second
	maxEventPing      = 300
)

type eventOptions struct {
	kinds []string
	close bool
	ping  time.Duration
}

func (g *Gateway) eventOptions(raw string) (eventOptions, bool) {
	values, err := url.ParseQuery(raw)
	if err != nil || len(values["types"]) != 1 || len(values["closeafter"]) != 1 || len(values["ping"]) != 1 {
		return eventOptions{}, false
	}
	closeAfter := values.Get("closeafter")
	ping, err := strconv.ParseUint(values.Get("ping"), 10, 64)
	if err != nil || (closeAfter != "state" && closeAfter != "no") {
		return eventOptions{}, false
	}
	types := values.Get("types")
	requested := make(map[string]bool)
	if types != "*" {
		names := strings.Split(types, ",")
		if len(names) > 32 {
			return eventOptions{}, false
		}
		for _, name := range names {
			if !jmapID.MatchString(name) {
				return eventOptions{}, false
			}
			requested[name] = true
		}
	}
	options := eventOptions{close: closeAfter == "state", ping: time.Duration(min(ping, maxEventPing)) * time.Second}
	for _, kind := range g.eventKinds() {
		if types == "*" || requested[kind] {
			options.kinds = append(options.kinds, kind)
		}
	}
	return options, true
}

func (g *Gateway) eventKinds() []string {
	supported := []string{"Mailbox", "Email", "EmailDelivery", "Thread", "Identity", "EmailSubmission"}
	if _, available := g.session["capabilities"].(object)[vacationCapability]; available {
		supported = append(supported, "VacationResponse")
	}
	return supported
}

type eventObservation struct {
	mailAt, vacationAt time.Time
	mail               map[string]string
	vacation           string
}

func (g *Gateway) eventStates(ctx context.Context, kinds []string) map[string]string {
	select {
	case g.gate <- struct{}{}:
		defer func() { <-g.gate }()
	default:
		// The stream can wait for an API mutation to finish.
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, eventPollTimeout)
	defer cancel()
	op := operation{g: g, ctx: ctx}
	defer func() {
		if op.closeIMAP != nil {
			op.closeIMAP()
		}
	}()
	result := make(map[string]string, len(kinds))
	cache := &g.eventCache
	for _, kind := range kinds {
		switch kind {
		case "Mailbox", "Email", "EmailDelivery", "Thread":
			if time.Since(cache.mailAt) >= eventPollInterval {
				cache.mail = nil
				if op.loadMail() == "" {
					cache.mail = map[string]string{"Mailbox": op.state("Mailbox"), "Email": op.state("Email"), "Thread": op.state("Thread")}
					cache.mail["EmailDelivery"] = g.history.track("Email").DeliveryState
				}
				cache.mailAt = time.Now()
			}
			if state := cache.mail[kind]; state != "" {
				result[kind] = state
			}
		case "VacationResponse":
			if g.sieveTLS == nil {
				continue
			}
			if time.Since(cache.vacationAt) >= eventPollInterval {
				cache.vacation = op.eventVacationState()
				cache.vacationAt = time.Now()
			}
			if cache.vacation != "" {
				result[kind] = cache.vacation
			}
		default:
			result[kind] = op.state(kind)
		}
	}
	return result
}

func (g *Gateway) accountStates(ctx context.Context, kinds []string) map[string]map[string]string {
	states := map[string]map[string]string{g.config.AccountID: g.eventStates(ctx, kinds)}
	for _, id := range sortedKeys(g.accounts) {
		if ctx.Err() != nil {
			break
		}
		states[id] = g.accounts[id].eventStates(ctx, kinds)
	}
	return states
}

func changedAccountStates(primary string, states map[string]map[string]string, last map[string]string, types []string) (object, map[string]string) {
	changed := make(object)
	delivered := make(map[string]string)
	for account, current := range states {
		delta := make(map[string]string)
		for kind, state := range current {
			key := kind
			if account != primary {
				key = account + "/" + kind
			}
			if (types == nil || contains(types, kind)) && state != last[key] {
				delivered[key] = state
				delta[kind] = state
			}
		}
		if len(delta) != 0 {
			changed[account] = delta
		}
	}
	return changed, delivered
}

func (op *operation) eventVacationState() string {
	client, closeClient, failure := op.vacationClient()
	if failure != "" {
		return ""
	}
	defer closeClient()
	settings, failure := client.getVacation()
	if failure != "" {
		return ""
	}
	return digest(settings)
}

func (g *Gateway) eventID(states map[string]string) string {
	raw, _ := json.Marshal(states)
	payload := base64.RawURLEncoding.EncodeToString(raw)
	return payload + "." + g.signCursor("event:"+payload)
}

func (g *Gateway) resumeEvents(token string) map[string]string {
	payload, signature, ok := strings.Cut(token, ".")
	if !ok || len(payload) > 16384 || !hmac.Equal([]byte(signature), []byte(g.signCursor("event:"+payload))) {
		return make(map[string]string)
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	var states map[string]string
	if err != nil || json.Unmarshal(raw, &states) != nil || states == nil {
		return make(map[string]string)
	}
	return states
}

func (g *Gateway) serveEvents(w http.ResponseWriter, r *http.Request) {
	options, ok := g.eventOptions(r.URL.RawQuery)
	if !ok {
		http.Error(w, "Invalid event-source parameters", http.StatusBadRequest)
		return
	}
	select {
	case g.eventSlots <- struct{}{}:
		defer func() { <-g.eventSlots }()
	default:
		w.Header().Set("Retry-After", "1")
		http.Error(w, "Event streams busy", http.StatusServiceUnavailable)
		return
	}
	controller := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	if controller.Flush() != nil {
		return
	}
	_ = controller.SetWriteDeadline(time.Time{})
	send := func(name, id string, value object) bool {
		_ = controller.SetWriteDeadline(time.Now().Add(eventWriteTimeout))
		defer controller.SetWriteDeadline(time.Time{})
		return writeEvent(w, name, id, value) && controller.Flush() == nil
	}
	poll := time.NewTimer(0)
	defer poll.Stop()
	var ping *time.Timer
	var pingAt <-chan time.Time
	if options.ping > 0 {
		ping = time.NewTimer(options.ping)
		pingAt = ping.C
		defer ping.Stop()
	}
	last := g.resumeEvents(r.Header.Get("Last-Event-ID"))
	ctx, cancel := context.WithCancel(r.Context())
	var observation <-chan map[string]map[string]string
	defer func() {
		cancel()
		if observation != nil {
			<-observation
		}
	}()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-g.eventsDone:
			return
		case <-pingAt:
			if !send("ping", "", object{"interval": uint64(options.ping / time.Second)}) {
				return
			}
			ping.Reset(options.ping)
		case <-poll.C:
			next := make(chan map[string]map[string]string, 1)
			observation = next
			go func() { next <- g.accountStates(ctx, options.kinds) }()
		case states := <-observation:
			observation = nil
			changed, delivered := changedAccountStates(g.config.AccountID, states, last, nil)
			if len(changed) != 0 {
				maps.Copy(last, delivered)
				data := object{"@type": "StateChange", "changed": changed}
				if !send("state", g.eventID(last), data) || options.close {
					return
				}
				if ping != nil {
					ping.Reset(options.ping)
				}
			}
			poll.Reset(eventPollInterval)
		}
	}
}

func writeEvent(w http.ResponseWriter, name, id string, value object) bool {
	raw, _ := json.Marshal(value)
	var prefix string
	if id != "" {
		prefix = "id: " + id + "\n"
	}
	_, err := fmt.Fprintf(w, "%sevent: %s\ndata: %s\n\n", prefix, name, raw)
	return err == nil
}
