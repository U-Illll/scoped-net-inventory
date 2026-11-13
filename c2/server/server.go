// Package server implements a lab-only command-and-control service.
//
// Guard rails baked into this package, all of them load-bearing:
//
//   - The server refuses to start without -lab (an explicit acknowledgement of
//     DISCLAIMER.md) and without a shared secret.
//   - Every request must carry a valid HMAC over its body and a timestamp inside
//     the skew window, so a captured beacon cannot be replayed.
//   - Implants may only be tasked with kinds in proto.KnownKinds(). An unknown
//     kind is rejected at enqueue time, not at the implant.
//   - The operator API is separate from the implant API and uses its own token.
//   - Task history is kept in memory only; nothing is persisted to disk.
//
// It is a teaching instrument for studying tasking protocol design against
// containers you own. See DISCLAIMER.md.
package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/U-Illll/scoped-net-inventory/c2/proto"
)

// Config configures a Server.
type Config struct {
	// Listen is the bind address. The caller is expected to keep this on a
	// loopback or container-internal interface.
	Listen string
	// Secret signs implant traffic.
	Secret []byte
	// OperatorToken authenticates the operator API.
	OperatorToken string
	// Skew is the accepted clock difference for signed requests.
	Skew time.Duration
	// DefaultSleep is the beacon interval handed to implants.
	DefaultSleepSeconds int
	// MaxTasksPerBeacon caps how much work one check-in can pull.
	MaxTasksPerBeacon int
}

// ImplantState is what the operator view knows about one implant.
type ImplantState struct {
	ID         string        `json:"id"`
	Hostname   string        `json:"hostname"`
	OS         string        `json:"os"`
	Arch       string        `json:"arch"`
	FirstSeen  time.Time     `json:"first_seen"`
	LastSeen   time.Time     `json:"last_seen"`
	BeaconSeq  int           `json:"beacon_seq"`
	Pending    int           `json:"pending"`
	LastResult *proto.Result `json:"last_result,omitempty"`
}

// Server is an in-memory C2 service.
type Server struct {
	cfg Config

	mu       sync.Mutex
	implants map[string]*ImplantState
	queue    map[string][]proto.Task // implant ID -> pending tasks
	seq      int
}

// New validates the config and returns a server. A zero or short secret is an
// error: an unsigned C2 channel is not a research instrument, it is a hazard.
func New(cfg Config) (*Server, error) {
	if len(cfg.Secret) < 16 {
		return nil, fmt.Errorf("shared secret must be at least 16 bytes")
	}
	if cfg.OperatorToken == "" {
		return nil, fmt.Errorf("operator token is required")
	}
	if cfg.Skew <= 0 {
		cfg.Skew = 60 * time.Second
	}
	if cfg.DefaultSleepSeconds <= 0 {
		cfg.DefaultSleepSeconds = 5
	}
	if cfg.MaxTasksPerBeacon <= 0 {
		cfg.MaxTasksPerBeacon = 4
	}
	return &Server{
		cfg:      cfg,
		implants: map[string]*ImplantState{},
		queue:    map[string][]proto.Task{},
	}, nil
}

// Handler returns the HTTP routes. Implant and operator APIs are mounted under
// distinct prefixes so a leaked implant secret cannot reach operator routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/implant/beacon", s.handleBeacon)
	mux.HandleFunc("/implant/result", s.handleResult)
	mux.HandleFunc("/operator/implants", s.handleImplants)
	mux.HandleFunc("/operator/task", s.handleTask)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})
	return mux
}

// readSigned reads the body of a signed implant request and verifies HMAC,
// timestamp and ImplantID presence. On failure it writes the response itself.
func (s *Server) readSigned(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return nil, false
	}
	ts := r.Header.Get("X-C2-Timestamp")
	sig := r.Header.Get("X-C2-Signature")
	if ts == "" || sig == "" {
		http.Error(w, "missing signature", http.StatusUnauthorized)
		return nil, false
	}
	if err := proto.CheckSkew(ts, s.cfg.Skew, time.Now()); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return nil, false
	}
	body := make([]byte, 0, 1024)
	buf := make([]byte, 4096)
	for {
		n, err := r.Body.Read(buf)
		body = append(body, buf[:n]...)
		if err != nil {
			break
		}
		if len(body) > 1<<20 {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return nil, false
		}
	}
	if !proto.Verify(s.cfg.Secret, ts, body, sig) {
		http.Error(w, "bad signature", http.StatusUnauthorized)
		return nil, false
	}
	return body, true
}

func (s *Server) handleBeacon(w http.ResponseWriter, r *http.Request) {
	body, ok := s.readSigned(w, r)
	if !ok {
		return
	}
	var b proto.Beacon
	if err := json.Unmarshal(body, &b); err != nil || b.ImplantID == "" {
		http.Error(w, "bad beacon", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	st, seen := s.implants[b.ImplantID]
	now := time.Now().UTC()
	if !seen {
		st = &ImplantState{ID: b.ImplantID, FirstSeen: now}
		s.implants[b.ImplantID] = st
	}
	st.Hostname, st.OS, st.Arch = b.Hostname, b.OS, b.Arch
	st.LastSeen = now
	st.BeaconSeq++

	pending := s.queue[b.ImplantID]
	if len(pending) > s.cfg.MaxTasksPerBeacon {
		pending = pending[:s.cfg.MaxTasksPerBeacon]
	}
	// Pop what we hand out so a task is delivered once.
	s.queue[b.ImplantID] = s.queue[b.ImplantID][len(pending):]
	st.Pending = len(s.queue[b.ImplantID])
	s.mu.Unlock()

	reply := proto.BeaconReply{
		Tasks:         pending,
		SleepSeconds:  s.cfg.DefaultSleepSeconds,
		JitterPercent: 20,
	}
	writeJSON(w, reply)
}

func (s *Server) handleResult(w http.ResponseWriter, r *http.Request) {
	body, ok := s.readSigned(w, r)
	if !ok {
		return
	}
	var res proto.Result
	if err := json.Unmarshal(body, &res); err != nil || res.ImplantID == "" {
		http.Error(w, "bad result", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	st, seen := s.implants[res.ImplantID]
	if !seen {
		st = &ImplantState{ID: res.ImplantID, FirstSeen: time.Now().UTC()}
		s.implants[res.ImplantID] = st
	}
	cp := res
	st.LastResult = &cp
	st.LastSeen = time.Now().UTC()
	s.mu.Unlock()

	log.Printf("result implant=%s task=%s kind=%s ok=%v dur=%dms",
		res.ImplantID, res.TaskID, res.Kind, res.OK, res.DurationMS)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) checkOperator(w http.ResponseWriter, r *http.Request) bool {
	got := r.Header.Get("X-Operator-Token")
	if subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.OperatorToken)) != 1 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	return true
}

func (s *Server) handleImplants(w http.ResponseWriter, r *http.Request) {
	if !s.checkOperator(w, r) {
		return
	}
	s.mu.Lock()
	out := make([]ImplantState, 0, len(s.implants))
	for _, st := range s.implants {
		cp := *st
		cp.Pending = len(s.queue[st.ID])
		out = append(out, cp)
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	writeJSON(w, map[string]any{"implants": out, "count": len(out)})
}

func (s *Server) handleTask(w http.ResponseWriter, r *http.Request) {
	if !s.checkOperator(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ImplantID string            `json:"implant_id"`
		Kind      string            `json:"kind"`
		Args      map[string]string `json:"args"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad task", http.StatusBadRequest)
		return
	}
	// The allowlist is enforced here, at the trust boundary, so an operator
	// typo cannot become an implant-side surprise.
	if !proto.IsKnownKind(req.Kind) {
		http.Error(w, fmt.Sprintf("task kind %q is not allowlisted", req.Kind), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	if _, ok := s.implants[req.ImplantID]; !ok {
		s.mu.Unlock()
		http.Error(w, "unknown implant", http.StatusNotFound)
		return
	}
	s.seq++
	task := proto.Task{
		ID:       newTaskID(s.seq),
		Kind:     req.Kind,
		Args:     req.Args,
		IssuedAt: time.Now().UTC(),
	}
	s.queue[req.ImplantID] = append(s.queue[req.ImplantID], task)
	pending := len(s.queue[req.ImplantID])
	s.mu.Unlock()

	writeJSON(w, map[string]any{"queued": task, "pending": pending})
}

func newTaskID(seq int) string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("t%s-%d", hex.EncodeToString(b[:]), seq)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// Run serves until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	if s.cfg.Listen == "" {
		return fmt.Errorf("listen address is required")
	}
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Printf("c2 lab server listening on %s (lab mode)", ln.Addr())
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
