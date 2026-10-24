// Package audit writes bounded local security events, never invocation content.
package audit

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var ErrAudit = errors.New("security audit unavailable")

type Permission struct {
	Server string `json:"server"`
	Tool   string `json:"tool"`
}
type Event struct {
	ItemID       string       `json:"item_id,omitempty"`
	RequestID    string       `json:"request_id"`
	Kind         string       `json:"kind"`
	Auth         string       `json:"auth,omitempty"`
	Actor        string       `json:"actor,omitempty"`
	Principal    string       `json:"principal,omitempty"`
	Target       string       `json:"target,omitempty"`
	Server       string       `json:"server,omitempty"`
	Tool         string       `json:"tool,omitempty"`
	Decision     string       `json:"decision,omitempty"`
	Reason       string       `json:"reason,omitempty"`
	Outcome      string       `json:"outcome"`
	Revision     int64        `json:"revision,omitempty"`
	BaseRevision int64        `json:"base_revision,omitempty"`
	Dispatched   bool         `json:"dispatched"`
	PolicyBefore string       `json:"policy_before,omitempty"`
	PolicyAfter  string       `json:"policy_after,omitempty"`
	Added        []Permission `json:"added,omitempty"`
	Removed      []Permission `json:"removed,omitempty"`
	Cause        string       `json:"cause,omitempty"`
}
type Sink struct {
	mu                     sync.Mutex
	dir, segment, state    string
	counter                uint64
	maxBytes, segmentBytes int64
	retention              time.Duration
	now                    func() time.Time
	identity               os.FileInfo
}

func RequestID() string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "unavailable"
	}
	return hex.EncodeToString(b[:])
}
func FromEnv() (*Sink, error) {
	raw := os.Getenv("GATEWAY_AUDIT_ENABLED")
	enabled := false
	var e error
	if raw != "" {
		enabled, e = strconv.ParseBool(raw)
		if e != nil {
			return nil, ErrAudit
		}
	}
	dir := os.Getenv("GATEWAY_AUDIT_DIR")
	if !enabled {
		if dir != "" {
			return nil, ErrAudit
		}
		return nil, nil
	}
	return New(dir)
}
func New(dir string) (*Sink, error) {
	if dir == "" {
		return nil, ErrAudit
	}
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, ErrAudit
	}
	st, e := os.Lstat(dir)
	if e != nil || !st.IsDir() || st.Mode().Perm() != 0700 || !owned(st) {
		return nil, ErrAudit
	}
	s := &Sink{dir: dir, state: "ok", maxBytes: 100 << 20, segmentBytes: 4 << 20, retention: 30 * 24 * time.Hour, now: time.Now, identity: st}
	if e = s.Record(Event{Kind: "audit", Outcome: "started", RequestID: RequestID()}); e != nil {
		return nil, e
	}
	return s, nil
}
func owned(st os.FileInfo) bool {
	v, ok := st.Sys().(*syscall.Stat_t)
	return ok && v.Uid == uint32(os.Geteuid())
}
func (s *Sink) State() string {
	if s == nil {
		return "disabled"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}
func (s *Sink) Record(event Event) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.append(event); e != nil {
		s.state = "degraded"
		return ErrAudit
	}
	s.state = "ok"
	return nil
}
func (s *Sink) append(event Event) error {
	for _, v := range []string{event.ItemID, event.RequestID, event.Kind, event.Auth, event.Actor, event.Principal, event.Target, event.Server, event.Tool, event.Decision, event.Reason, event.Outcome, event.Cause, event.PolicyBefore, event.PolicyAfter} {
		if len(v) > 256 || strings.ContainsAny(v, "\r\n\x00") {
			return ErrAudit
		}
	}
	if event.RequestID == "" {
		event.RequestID = RequestID()
	}
	for _, p := range append(append([]Permission{}, event.Added...), event.Removed...) {
		if len(p.Server) > 128 || len(p.Tool) > 128 {
			return ErrAudit
		}
	}
	payload, e := json.Marshal(struct {
		Time string `json:"time"`
		Event
	}{s.now().UTC().Format(time.RFC3339Nano), event})
	if e != nil || len(payload) > 4<<20 {
		return ErrAudit
	}
	payload = append(payload, '\n')
	st, e := os.Lstat(s.dir)
	if e != nil || !os.SameFile(st, s.identity) || !st.IsDir() || st.Mode().Perm() != 0700 {
		return ErrAudit
	}
	entries, e := os.ReadDir(s.dir)
	if e != nil {
		return ErrAudit
	}
	type item struct {
		name string
		size int64
		at   time.Time
	}
	files := []item{}
	var total int64
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "audit-") || !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		info, e := entry.Info()
		if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !owned(info) {
			return ErrAudit
		}
		if s.now().Sub(info.ModTime()) > s.retention {
			if os.Remove(filepath.Join(s.dir, entry.Name())) != nil {
				return ErrAudit
			}
			if s.segment == entry.Name() {
				s.segment = ""
			}
			continue
		}
		files = append(files, item{entry.Name(), info.Size(), info.ModTime()})
		total += info.Size()
	}
	sort.Slice(files, func(i, j int) bool { return files[i].at.Before(files[j].at) })
	for len(files) > 0 && total+int64(len(payload)) > s.maxBytes {
		f := files[0]
		files = files[1:]
		if os.Remove(filepath.Join(s.dir, f.name)) != nil {
			return ErrAudit
		}
		total -= f.size
		if s.segment == f.name {
			s.segment = ""
		}
	}
	if total+int64(len(payload)) > s.maxBytes {
		return ErrAudit
	}
	if s.segment != "" {
		info, e := os.Lstat(filepath.Join(s.dir, s.segment))
		if e != nil || info.Size()+int64(len(payload)) > s.segmentBytes {
			s.segment = ""
		}
	}
	if s.segment == "" {
		s.counter++
		s.segment = fmt.Sprintf("audit-%020d-%s-%d.jsonl", s.now().UnixNano(), RequestID(), s.counter)
	}
	f, e := os.OpenFile(filepath.Join(s.dir, s.segment), os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if e != nil {
		return ErrAudit
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || !owned(info) || info.Mode().Perm() != 0600 {
		return ErrAudit
	}
	n, e := f.Write(payload)
	if e != nil || n != len(payload) {
		return ErrAudit
	}
	return f.Sync()
}
