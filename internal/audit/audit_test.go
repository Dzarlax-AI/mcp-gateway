package audit

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBoundedAuditAndLoss(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	s, e := New(dir)
	if e != nil {
		t.Fatal(e)
	}
	s.maxBytes = 1600
	s.segmentBytes = 400
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e := s.Record(Event{Kind: "decision", Principal: "synthetic-principal", Outcome: "denied"}); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	files, _ := os.ReadDir(dir)
	var size int64
	for _, f := range files {
		st, _ := f.Info()
		size += st.Size()
		b, _ := os.ReadFile(filepath.Join(dir, f.Name()))
		if strings.Contains(string(b), "arguments") || st.Mode().Perm() != 0600 {
			t.Fatal("unsafe audit")
		}
	}
	if size > s.maxBytes {
		t.Fatal("cap exceeded")
	}
	s.now = func() time.Time { return time.Now().Add(31 * 24 * time.Hour) }
	if e := s.Record(Event{Kind: "decision", Outcome: "ok"}); e != nil {
		t.Fatal(e)
	}
	if e := os.Rename(dir, dir+"-old"); e != nil {
		t.Fatal(e)
	}
	os.Symlink(dir+"-old", dir)
	if s.Record(Event{Outcome: "ok"}) == nil || s.State() != "degraded" {
		t.Fatal("sink loss hidden")
	}
}
func TestDisabledAndConfiguration(t *testing.T) {
	var s *Sink
	if s.State() != "disabled" || s.Record(Event{}) != nil {
		t.Fatal("disabled")
	}
	dir := t.TempDir()
	os.Chmod(dir, 0755)
	if _, e := New(dir); e == nil {
		t.Fatal("public directory accepted")
	}
	t.Setenv("GATEWAY_AUDIT_ENABLED", "true")
	t.Setenv("GATEWAY_AUDIT_DIR", "")
	if _, e := FromEnv(); e == nil {
		t.Fatal("partial config")
	}
}
