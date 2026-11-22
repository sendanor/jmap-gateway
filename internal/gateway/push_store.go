package gateway

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	pushFile          = "push-subscriptions.json"
	maxPushRecords    = 8
	maxPushAge        = 7 * 24 * time.Hour
	maxPushStoreBytes = 1 << 20
	maxPushVerifies   = 12
)

type pushSubscription struct {
	Device   string
	URL      string
	Keys     *pushKeys `json:",omitempty"`
	Expires  time.Time
	Types    []string
	Code     string
	Verified bool
	Last     map[string]string `json:",omitempty"`
	RetryAt  time.Time
}

type pushStore struct {
	mu         sync.Mutex
	records    map[string]pushSubscription
	credential string
	dir        string
	origins    map[string]bool
	client     *http.Client
	files      atomicFiles
	failed     bool
	cancel     context.CancelFunc
	done       chan struct{}
	verifies   []time.Time
}

func (g *Gateway) openPush() error {
	p := &pushStore{records: make(map[string]pushSubscription), dir: g.config.StateDir, files: localAtomicFiles,
		credential: g.signCursor("push-credentials:" + hex.EncodeToString(g.auth[:])),
		origins:    make(map[string]bool)}
	for _, raw := range g.config.PushOrigins {
		u, ok := pushURL(raw)
		if !ok || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery {
			return errors.New("PushOrigins entries must be HTTPS origins")
		}
		p.origins[pushOrigin(u)] = true
	}
	tlsConfig, err := upstreamTLS(Upstream{CAFile: g.config.PushCAFile})
	if err != nil {
		return err
	}
	p.client = &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig, DisableKeepAlives: true},
		Timeout: pushRequestLimit, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if err := p.load(); err != nil {
		return err
	}
	g.push = p
	if len(p.origins) != 0 {
		ctx, cancel := context.WithCancel(context.Background())
		p.cancel, p.done = cancel, make(chan struct{})
		go g.runPush(ctx)
	}
	return nil
}

func (p *pushStore) stop() {
	if p.cancel != nil {
		p.cancel()
		<-p.done
	}
}

type pushDisk struct {
	Credential string
	Records    map[string]pushSubscription
}

func (p *pushStore) load() error {
	f, err := os.Open(filepath.Join(p.dir, pushFile))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return errors.New("cannot open push state")
	}
	defer f.Close()
	raw, large, err := take(f, maxPushStoreBytes)
	var disk pushDisk
	if err != nil || large || json.Unmarshal(raw, &disk) != nil || disk.Records == nil || len(disk.Records) > maxPushRecords {
		return errors.New("invalid push state")
	}
	if disk.Credential != p.credential {
		return p.save(p.records)
	}
	p.records = disk.Records
	return p.prune(time.Now())
}

func (p *pushStore) save(next map[string]pushSubscription) error {
	err := p.files.replace(p.dir, pushFile, ".push-*", func(w io.Writer) error {
		return json.NewEncoder(w).Encode(pushDisk{p.credential, next})
	})
	if err != nil {
		p.failed = true
		return errors.New("cannot persist push state")
	}
	p.records = next
	return nil
}

func (p *pushStore) prune(now time.Time) error {
	next := maps.Clone(p.records)
	for id, sub := range next {
		if !now.Before(sub.Expires) || !p.allows(sub.URL) {
			delete(next, id)
		}
	}
	if len(next) != len(p.records) {
		return p.save(next)
	}
	return nil
}

func (p *pushStore) verificationBudget(now time.Time) int {
	for len(p.verifies) != 0 && now.Sub(p.verifies[0]) >= time.Minute {
		p.verifies = p.verifies[1:]
	}
	return maxPushVerifies - len(p.verifies)
}

func (g *Gateway) runPush(ctx context.Context) {
	defer close(g.push.done)
	ticker := time.NewTicker(eventPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			g.pollPush(ctx)
		}
	}
}

func (g *Gateway) pollPush(ctx context.Context) {
	p := g.push
	p.mu.Lock()
	if p.failed || p.prune(time.Now()) != nil {
		p.mu.Unlock()
		return
	}
	wanted := make(map[string]bool)
	now := time.Now()
	for _, sub := range p.records {
		if sub.Verified && !now.Before(sub.RetryAt) {
			for _, kind := range g.eventKinds() {
				if sub.Types == nil || contains(sub.Types, kind) {
					wanted[kind] = true
				}
			}
		}
	}
	p.mu.Unlock()
	if len(wanted) == 0 {
		return
	}
	states := g.accountStates(ctx, sortedKeys(wanted))
	p.mu.Lock()
	ids := sortedKeys(p.records)
	p.mu.Unlock()
	for _, id := range ids {
		p.deliverPush(ctx, id, g.config.AccountID, states)
	}
}

func (p *pushStore) deliverPush(ctx context.Context, id, account string, states map[string]map[string]string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failed {
		return
	}
	sub := p.records[id]
	now := time.Now()
	if !sub.Verified || now.Before(sub.RetryAt) || !now.Before(sub.Expires) || ctx.Err() != nil {
		return
	}
	changed, delivered := changedAccountStates(account, states, sub.Last, sub.Types)
	if len(changed) == 0 {
		return
	}
	data := object{"@type": "StateChange", "changed": changed}
	status, retry := p.post(ctx, sub, data)
	if status == 0 && ctx.Err() != nil {
		// A deliberate shutdown is not a receiver failure. Preserve the last
		// acknowledgement for the next worker instead of imposing backoff.
		return
	}
	next := maps.Clone(p.records)
	switch {
	case status >= 200 && status < 300:
		last := make(map[string]string, len(sub.Last)+len(delivered))
		maps.Copy(last, sub.Last)
		maps.Copy(last, delivered)
		sub.Last, sub.RetryAt = last, time.Time{}
		next[id] = sub
	case status == http.StatusNotFound || status == http.StatusGone:
		delete(next, id)
	default:
		sub.RetryAt = pushRetry(time.Now(), retry)
		next[id] = sub
	}
	_ = p.save(next)
}
