// Package catalog provides a bounded, process-local cache of upstream MCP tools.
package catalog

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"mcp-gateway/internal/config"
	"mcp-gateway/internal/store"
	"mcp-gateway/internal/upstream"
)

const (
	defaultTTL      = 60 * time.Second
	maxEntries      = 256
	maxTools        = 500
	maxCatalogBytes = 1 << 20
	maxTotalBytes   = 64 << 20
	maxRefreshes    = 4
	maxFlights      = 256
	refreshTimeout  = 5 * time.Second
)

var ErrCatalog = errors.New("tool catalog unavailable or invalid")

// Connection contains inputs which determine an upstream catalog. Token is never
// included in errors or catalog values.
type Connection struct {
	ID        string
	Revision  int64
	Server    config.Server
	Token     string
	Allowlist []string
}

// FromSnapshot resolves a server and its exact credential from one immutable snapshot.
func FromSnapshot(snapshot store.Snapshot, id string) (Connection, error) {
	if snapshot.Config == nil {
		return Connection{}, ErrCatalog
	}
	srv, ok := snapshot.Config.Servers[id]
	if !ok || id == "" {
		return Connection{}, ErrCatalog
	}
	var token string
	if srv.TokenEnv != "" {
		token = os.Getenv(srv.TokenEnv)
	} else if srv.TokenRef != "" {
		var err error
		token, err = store.ResolveSnapshotSecret(snapshot, id)
		if err != nil {
			return Connection{}, ErrCatalog
		}
	}
	if (srv.TokenEnv != "" || srv.TokenRef != "") && !config.ValidCredential(srv.AuthHeader, token) {
		return Connection{}, ErrCatalog
	}
	if !snapshot.Config.AllowsEndpoint(srv.URL) {
		return Connection{}, ErrCatalog
	}
	allow := append([]string(nil), snapshot.Config.HTTPSAllowlist...)
	sort.Strings(allow)
	return Connection{ID: id, Revision: snapshot.Revision, Server: srv, Token: token, Allowlist: allow}, nil
}

// Fingerprint binds cached metadata to every upstream connection input.
func Fingerprint(c Connection) [32]byte {
	v := struct {
		ID, URL, Header, Source, Token string
		Allowlist                      []string
	}{
		ID: c.ID, URL: c.Server.URL, Header: c.Server.AuthHeader,
		Source: c.Server.TokenRef + "\x00" + c.Server.TokenEnv, Token: c.Token,
		Allowlist: append([]string(nil), c.Allowlist...),
	}
	sort.Strings(v.Allowlist)
	b, _ := json.Marshal(v)
	return sha256.Sum256(b)
}

type entry struct {
	fingerprint       [32]byte
	revision          int64
	authorityRevision int64
	authoritative     bool
	at                time.Time
	tools             []*mcp.Tool
	bytes             int
	used              uint64
}
type flight struct {
	id       string
	done     chan struct{}
	tools    []*mcp.Tool
	err      error
	revision int64
}
type loader func(context.Context, Connection) ([]*mcp.Tool, error)
type clock func() time.Time
type options struct {
	ttl                                                                time.Duration
	now                                                                clock
	load                                                               loader
	maxEntries, maxTools, maxCatalogBytes, maxTotalBytes, maxRefreshes int
	refreshTimeout                                                     time.Duration
}

// Provider owns immutable catalog snapshots. Close cancels shared refreshes.
type Provider struct {
	mu                   sync.Mutex
	entries              map[string]*entry
	flights              map[string]*flight
	generation           map[string]uint64
	target               map[string][32]byte
	targetSet            map[string]bool
	authorityRevision    map[string]int64
	retiredRevisionFloor int64
	bytes                int
	sequence             uint64
	closed               bool
	ctx                  context.Context
	cancel               context.CancelFunc
	sem                  chan struct{}
	opts                 options
}

func New() *Provider { return newProvider(options{}) }
func newProvider(o options) *Provider {
	if o.ttl <= 0 {
		o.ttl = defaultTTL
	}
	if o.now == nil {
		o.now = time.Now
	}
	if o.load == nil {
		o.load = loadUpstream
	}
	if o.maxEntries <= 0 {
		o.maxEntries = maxEntries
	}
	if o.maxTools <= 0 {
		o.maxTools = maxTools
	}
	if o.maxCatalogBytes <= 0 {
		o.maxCatalogBytes = maxCatalogBytes
	}
	if o.maxTotalBytes <= 0 {
		o.maxTotalBytes = maxTotalBytes
	}
	if o.maxRefreshes <= 0 {
		o.maxRefreshes = maxRefreshes
	}
	if o.refreshTimeout <= 0 {
		o.refreshTimeout = refreshTimeout
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Provider{entries: map[string]*entry{}, flights: map[string]*flight{}, generation: map[string]uint64{}, target: map[string][32]byte{}, targetSet: map[string]bool{}, authorityRevision: map[string]int64{}, ctx: ctx, cancel: cancel, sem: make(chan struct{}, o.maxRefreshes), opts: o}
}

func loadUpstream(ctx context.Context, c Connection) ([]*mcp.Tool, error) {
	s, closeFn, err := upstream.ConnectWithToken(ctx, c.Server, c.Token)
	if err != nil {
		return nil, ErrCatalog
	}
	defer closeFn()
	t, err := upstream.Tools(ctx, s)
	if err != nil {
		return nil, ErrCatalog
	}
	return t, nil
}

func validConnection(c Connection) bool {
	if !config.ValidIdentifier(c.ID) || c.Server.URL == "" {
		return false
	}
	if !config.ValidURL(c.Server.URL) {
		if !config.ValidHTTPS(c.Server.URL) {
			return false
		}
		allowed := false
		for _, endpoint := range c.Allowlist {
			if endpoint == c.Server.URL {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}
	if c.Server.AuthHeader != "" && !config.ValidAuthHeader(c.Server.AuthHeader) {
		return false
	}
	if (c.Server.TokenEnv != "" || c.Server.TokenRef != "") && !config.ValidCredential(c.Server.AuthHeader, c.Token) {
		return false
	}
	return true
}

func (p *Provider) Get(ctx context.Context, c Connection, force bool) ([]*mcp.Tool, error) {
	tools, _, err := p.GetWithStatus(ctx, c, force)
	return tools, err
}

// GetWithStatus reports whether this call joined or performed a metadata refresh.
func (p *Provider) GetWithStatus(ctx context.Context, c Connection, force bool) ([]*mcp.Tool, bool, error) {
	if ctx == nil || c.Revision < 0 || !validConnection(c) {
		return nil, false, ErrCatalog
	}
	fp := Fingerprint(c)
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, false, ErrCatalog
	}
	if e := p.entries[c.ID]; e != nil && e.fingerprint == fp && c.Revision >= e.revision && p.opts.now().Sub(e.at) < p.opts.ttl && !force {
		p.sequence++
		e.used = p.sequence
		out, err := cloneTools(e.tools)
		p.mu.Unlock()
		return out, false, err
	}
	oldGeneration, oldGenerationSet := p.generation[c.ID]
	oldTarget, oldTargetSet := p.target[c.ID], p.targetSet[c.ID]
	oldAuthorityRevision, authorityExisted := p.authorityRevision[c.ID]
	if !authorityExisted {
		p.authorityRevision[c.ID] = p.retiredRevisionFloor
	}
	if !p.targetSet[c.ID] {
		p.target[c.ID], p.targetSet[c.ID] = fp, true
	} else if p.target[c.ID] != fp {
		p.generation[c.ID]++
		p.target[c.ID] = fp
	}
	gen := p.generation[c.ID]
	key := c.ID + ":" + string(fp[:]) + ":" + strconv.FormatUint(gen, 10)
	if f := p.flights[key]; f != nil {
		if c.Revision > f.revision {
			f.revision = c.Revision
		}
		p.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, true, ctx.Err()
		case <-p.ctx.Done():
			return nil, true, ErrCatalog
		case <-f.done:
		}
		if f.err != nil {
			return nil, true, ErrCatalog
		}
		out, err := cloneTools(f.tools)
		return out, true, err
	}
	if len(p.flights) >= maxFlights {
		if oldGenerationSet {
			p.generation[c.ID] = oldGeneration
		} else {
			delete(p.generation, c.ID)
		}
		if oldTargetSet {
			p.target[c.ID], p.targetSet[c.ID] = oldTarget, true
		} else {
			delete(p.target, c.ID)
			delete(p.targetSet, c.ID)
		}
		if authorityExisted {
			p.authorityRevision[c.ID] = oldAuthorityRevision
		} else {
			delete(p.authorityRevision, c.ID)
		}
		p.mu.Unlock()
		return nil, false, ErrCatalog
	}
	f := &flight{id: c.ID, done: make(chan struct{}), revision: c.Revision}
	p.flights[key] = f
	p.mu.Unlock()
	go p.refresh(c, key, f, gen, fp)
	select {
	case <-ctx.Done():
		return nil, true, ctx.Err()
	case <-p.ctx.Done():
		return nil, true, ErrCatalog
	case <-f.done:
	}
	if f.err != nil {
		return nil, true, ErrCatalog
	}
	out, err := cloneTools(f.tools)
	return out, true, err
}

func (p *Provider) refresh(c Connection, key string, f *flight, gen uint64, fp [32]byte) {
	fetchCtx, cancel := context.WithTimeout(p.ctx, p.opts.refreshTimeout)
	defer cancel()
	select {
	case p.sem <- struct{}{}:
	case <-fetchCtx.Done():
		p.finish(c.ID, key, f, nil, ErrCatalog, gen, c.Revision, fp)
		return
	case <-p.ctx.Done():
		p.finish(c.ID, key, f, nil, ErrCatalog, gen, c.Revision, fp)
		return
	}
	tools, err := p.opts.load(fetchCtx, c)
	if fetchCtx.Err() != nil {
		err = ErrCatalog
	}
	<-p.sem
	p.finish(c.ID, key, f, tools, err, gen, c.Revision, fp)
}

func (p *Provider) finish(id, key string, f *flight, tools []*mcp.Tool, err error, gen uint64, revision int64, fp [32]byte) {
	if err == nil {
		tools, _, err = validateClone(tools, p.opts.maxTools, p.opts.maxCatalogBytes)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.flights[key] == f {
		delete(p.flights, key)
	}
	if f.revision > revision {
		revision = f.revision
	}
	if err == nil && !p.closed && p.generation[id] == gen && p.authorityRevision[id] <= revision {
		p.putLocked(id, &entry{fingerprint: fp, revision: revision, at: p.opts.now(), tools: tools, bytes: toolBytes(tools)})
	}
	f.tools = tools
	f.err = err
	close(f.done)
	p.cleanupStateLocked(id)
}

func (p *Provider) Publish(c Connection, revision int64, at time.Time, tools []*mcp.Tool) error {
	if revision < 0 || at.IsZero() || !validConnection(c) {
		return ErrCatalog
	}
	cloned, size, err := validateClone(tools, p.opts.maxTools, p.opts.maxCatalogBytes)
	if err != nil {
		return ErrCatalog
	}
	fp := Fingerprint(c)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrCatalog
	}
	if revision < p.retiredRevisionFloor && !p.hasLiveStateLocked(c.ID) {
		return ErrCatalog
	}
	if revision < p.authorityRevision[c.ID] {
		return ErrCatalog
	}
	if old := p.entries[c.ID]; old != nil {
		if old.fingerprint == fp && old.authoritative && at.Before(old.at) {
			return ErrCatalog
		}
	}
	p.authorityRevision[c.ID] = revision
	p.generation[c.ID]++
	p.target[c.ID], p.targetSet[c.ID] = fp, true
	p.putLocked(c.ID, &entry{fingerprint: fp, revision: revision, authorityRevision: revision, authoritative: true, at: at, tools: cloned, bytes: size})
	return nil
}

func (p *Provider) Invalidate(id string, revision int64) {
	if id == "" || revision < 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || revision < p.authorityRevision[id] {
		return
	}
	if revision < p.retiredRevisionFloor && !p.hasLiveStateLocked(id) {
		return
	}
	p.authorityRevision[id] = revision
	p.generation[id]++
	delete(p.target, id)
	delete(p.targetSet, id)
	// Runtime snapshot revisions do not override an authoritative invalidation.
	// A newer committed publication was already protected by authorityRevision.
	if e := p.entries[id]; e != nil {
		p.bytes -= e.bytes
		delete(p.entries, id)
	}
	p.cleanupStateLocked(id)
}

func (p *Provider) putLocked(id string, e *entry) {
	if old := p.entries[id]; old != nil {
		p.bytes -= old.bytes
		delete(p.entries, id)
	}
	if e.bytes > p.opts.maxTotalBytes {
		p.cleanupStateLocked(id)
		return
	}
	p.sequence++
	e.used = p.sequence
	p.entries[id] = e
	p.bytes += e.bytes
	for len(p.entries) > p.opts.maxEntries || p.bytes > p.opts.maxTotalBytes {
		var victim string
		var oldest uint64 = ^uint64(0)
		for k, v := range p.entries {
			if v.used < oldest {
				victim, oldest = k, v.used
			}
		}
		if victim == "" {
			break
		}
		p.bytes -= p.entries[victim].bytes
		delete(p.entries, victim)
		p.cleanupStateLocked(victim)
	}
}

func (p *Provider) cleanupStateLocked(id string) {
	if p.entries[id] != nil {
		return
	}
	for _, f := range p.flights {
		if f.id == id {
			return
		}
	}
	if revision := p.authorityRevision[id]; revision > p.retiredRevisionFloor {
		p.retiredRevisionFloor = revision
	}
	delete(p.generation, id)
	delete(p.target, id)
	delete(p.targetSet, id)
	delete(p.authorityRevision, id)
}

func (p *Provider) hasLiveStateLocked(id string) bool {
	if p.entries[id] != nil {
		return true
	}
	for _, f := range p.flights {
		if f.id == id {
			return true
		}
	}
	return false
}

func (p *Provider) Close() {
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		p.cancel()
		for id, e := range p.entries {
			p.bytes -= e.bytes
			delete(p.entries, id)
		}
	}
	p.mu.Unlock()
}

func validateClone(in []*mcp.Tool, maxN, maxBytes int) ([]*mcp.Tool, int, error) {
	if len(in) > maxN {
		return nil, 0, ErrCatalog
	}
	out := make([]*mcp.Tool, 0, len(in))
	total := 0
	names := make(map[string]bool, len(in))
	for _, t := range in {
		if t == nil {
			return nil, 0, ErrCatalog
		}
		if !config.ValidIdentifier(t.Name) || names[t.Name] || len(t.Description) > 16<<10 {
			return nil, 0, ErrCatalog
		}
		names[t.Name] = true
		b, err := json.Marshal(t)
		if err != nil {
			return nil, 0, ErrCatalog
		}
		total += len(b)
		if total > maxBytes {
			return nil, 0, ErrCatalog
		}
		var cp mcp.Tool
		if json.Unmarshal(b, &cp) != nil {
			return nil, 0, ErrCatalog
		}
		out = append(out, &cp)
	}
	return out, total, nil
}
func cloneTools(in []*mcp.Tool) ([]*mcp.Tool, error) {
	out, _, err := validateClone(in, maxTools, maxCatalogBytes)
	if err != nil {
		return nil, ErrCatalog
	}
	return out, nil
}
func toolBytes(in []*mcp.Tool) int {
	n := 0
	for _, t := range in {
		b, _ := json.Marshal(t)
		n += len(b)
	}
	return n
}
