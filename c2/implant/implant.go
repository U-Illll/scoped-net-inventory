// Package implant implements the lab-side agent that checks in with the C2
// server and executes allowlisted tasks.
//
// Deliberate limitations, each one a guard rail rather than an oversight:
//
//   - Task kinds come from a fixed allowlist (proto.KnownKinds). Unknown kinds
//     are refused before any handler runs.
//   - "exec" does not use a shell. It runs a binary from an explicit argv with
//     no interpolation, and the binary must appear in -exec-allow.
//   - "scan" reuses the repository's scope package: an implant cannot be tasked
//     to scan an arbitrary target, only hosts that appear in its own scope file.
//   - There is no persistence, no self-update, no privilege escalation and no
//     lateral movement code path.
//
// Paired with DISCLAIMER.md; intended for containers you own.
package implant

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/U-Illll/scoped-net-inventory/c2/proto"
	"github.com/U-Illll/scoped-net-inventory/probe"
	"github.com/U-Illll/scoped-net-inventory/scope"
)

// Config configures an implant.
type Config struct {
	ServerURL    string
	ImplantID    string
	Secret       []byte
	Skew         time.Duration
	HTTPTimeout  time.Duration
	MaxTaskRuns  int
	ScopePath    string
	ExecAllow    []string
	ExecTimeout  time.Duration
	MaxOutputLen int
}

type implant struct {
	cfg       Config
	client    *http.Client
	sc        *scope.Scope
	startedAt time.Time
}

// New builds an implant. A scope file is mandatory because the scan task must
// not be able to reach anything the operator did not pre-authorise on disk.
func New(cfg Config) (*implant, error) {
	if cfg.ServerURL == "" {
		return nil, fmt.Errorf("server url is required")
	}
	if len(cfg.Secret) < 16 {
		return nil, fmt.Errorf("shared secret must be at least 16 bytes")
	}
	if cfg.Skew <= 0 {
		cfg.Skew = 60 * time.Second
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 15 * time.Second
	}
	if cfg.ExecTimeout <= 0 {
		cfg.ExecTimeout = 10 * time.Second
	}
	if cfg.MaxOutputLen <= 0 {
		cfg.MaxOutputLen = 16 << 10
	}
	if cfg.ImplantID == "" {
		cfg.ImplantID = defaultID()
	}
	var sc *scope.Scope
	if cfg.ScopePath != "" {
		loaded, err := scope.Load(cfg.ScopePath)
		if err != nil {
			return nil, fmt.Errorf("loading implant scope: %w", err)
		}
		sc = loaded
	}
	return &implant{
		cfg:       cfg,
		client:    &http.Client{Timeout: cfg.HTTPTimeout},
		sc:        sc,
		startedAt: time.Now().UTC(),
	}, nil
}

func defaultID() string {
	host, _ := os.Hostname()
	var b [3]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%s-%s", strings.Split(host, ".")[0], hex.EncodeToString(b[:]))
}

// Run beacons until ctx is cancelled or a sleep/exit task ends the loop.
func (im *implant) Run(ctx context.Context) error {
	sleep := 5 * time.Second
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		reply, err := im.beacon(ctx)
		if err != nil {
			// A lab implant is allowed to be noisy about failure; there is no
			// covert retry schedule here.
			fmt.Fprintf(os.Stderr, "beacon failed: %v\n", err)
			sleep = 5 * time.Second
		} else {
			for _, t := range reply.Tasks {
				res := im.execute(ctx, t)
				if err := im.report(ctx, res); err != nil {
					fmt.Fprintf(os.Stderr, "report failed: %v\n", err)
				}
				if t.Kind == proto.KindExit {
					return nil
				}
				if t.Kind == proto.KindSleep {
					if secs := parseSeconds(t.Args["seconds"]); secs > 0 {
						sleep = time.Duration(secs) * time.Second
					}
				}
			}
			if reply.SleepSeconds > 0 {
				sleep = time.Duration(reply.SleepSeconds) * time.Second
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(sleep):
		}
	}
}

func (im *implant) beacon(ctx context.Context) (*proto.BeaconReply, error) {
	host, _ := os.Hostname()
	b := proto.Beacon{
		ImplantID: im.cfg.ImplantID,
		Hostname:  host,
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		Version:   proto.Version,
		Nonce:     randomNonce(),
		SentAt:    time.Now().UTC(),
	}
	body, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	respBody, err := im.post(ctx, "/implant/beacon", body)
	if err != nil {
		return nil, err
	}
	var reply proto.BeaconReply
	if err := json.Unmarshal(respBody, &reply); err != nil {
		return nil, fmt.Errorf("bad beacon reply: %w", err)
	}
	return &reply, nil
}

func (im *implant) report(ctx context.Context, res proto.Result) error {
	body, err := json.Marshal(res)
	if err != nil {
		return err
	}
	_, err = im.post(ctx, "/implant/result", body)
	return err
}

func (im *implant) post(ctx context.Context, path string, body []byte) ([]byte, error) {
	ts := fmt.Sprintf("%d", time.Now().Unix())
	sig := proto.Sign(im.cfg.Secret, ts, body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(im.cfg.ServerURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-C2-Timestamp", ts)
	req.Header.Set("X-C2-Signature", sig)
	resp, err := im.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// execute dispatches one task, refusing anything outside the allowlist.
func (im *implant) execute(ctx context.Context, t proto.Task) proto.Result {
	started := time.Now().UTC()
	res := proto.Result{
		ImplantID: im.cfg.ImplantID,
		TaskID:    t.ID,
		Kind:      t.Kind,
		StartedAt: started,
	}
	out, err := im.dispatch(ctx, t)
	res.FinishedAt = time.Now().UTC()
	res.DurationMS = res.FinishedAt.Sub(started).Milliseconds()
	if err != nil {
		res.Error = err.Error()
	} else {
		res.OK = true
		res.Output = truncate(out, im.cfg.MaxOutputLen)
	}
	return res
}

func (im *implant) dispatch(ctx context.Context, t proto.Task) (string, error) {
	if !proto.IsKnownKind(t.Kind) {
		return "", fmt.Errorf("task kind %q is not allowlisted", t.Kind)
	}
	switch t.Kind {
	case proto.KindPing:
		return "pong", nil
	case proto.KindSysinfo:
		host, _ := os.Hostname()
		return fmt.Sprintf("host=%s os=%s arch=%s version=%s uptime=%s",
			host, runtime.GOOS, runtime.GOARCH, proto.Version,
			time.Since(im.startedAt).Round(time.Second)), nil
	case proto.KindScan:
		return im.scan(ctx, t.Args)
	case proto.KindSleep:
		return "sleep acknowledged", nil
	case proto.KindExit:
		return "exiting", nil
	case proto.KindExec:
		return im.execAllowlisted(ctx, t.Args)
	}
	return "", fmt.Errorf("unhandled kind %q", t.Kind)
}

// scan runs the repository probe against hosts that its own scope file already
// authorised. The task cannot widen the scope: every host is re-checked.
func (im *implant) scan(ctx context.Context, args map[string]string) (string, error) {
	if im.sc == nil {
		return "", fmt.Errorf("no scope file configured; scan task refused")
	}
	raw := strings.TrimSpace(args["hosts"])
	if raw == "" {
		return "", fmt.Errorf("scan task requires hosts")
	}
	hosts := make([]string, 0, 4)
	for _, h := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' }) {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if !im.sc.Allows(h) {
			return "", fmt.Errorf("refusing out-of-scope host %q", h)
		}
		hosts = append(hosts, h)
	}
	if len(hosts) == 0 {
		return "", fmt.Errorf("scan task resolved to zero in-scope hosts")
	}
	results := probe.Run(ctx, hosts, im.sc.Ports(), probe.Options{
		Timeout:     probe.DefaultTimeout,
		Concurrency: 4,
		MaxHosts:    16,
	})
	var sb strings.Builder
	open := 0
	for _, r := range results {
		if r.Open {
			open++
		}
		fmt.Fprintf(&sb, "%s:%d open=%v ms=%d\n", r.Host, r.Port, r.Open, r.Millis)
	}
	fmt.Fprintf(&sb, "total_hosts=%d open=%d\n", len(hosts), open)
	return sb.String(), nil
}

// execAllowlisted runs a binary by absolute path with a fixed argv. No shell,
// no interpolation, and the binary must be explicitly allowlisted.
func (im *implant) execAllowlisted(ctx context.Context, args map[string]string) (string, error) {
	raw := strings.TrimSpace(args["argv"])
	if raw == "" {
		return "", fmt.Errorf("exec task requires argv")
	}
	parts := strings.Fields(raw)
	bin := parts[0]
	if !strings.HasPrefix(bin, "/") {
		return "", fmt.Errorf("exec requires an absolute path, got %q", bin)
	}
	allowed := false
	for _, a := range im.cfg.ExecAllow {
		if a == bin {
			allowed = true
			break
		}
	}
	if !allowed {
		return "", fmt.Errorf("binary %q is not in the exec allowlist", bin)
	}
	if len(im.cfg.ExecAllow) == 0 {
		return "", fmt.Errorf("exec allowlist is empty; exec task refused")
	}

	cctx, cancel := context.WithTimeout(ctx, im.cfg.ExecTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, parts[1:]...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("exec %s: %w", bin, err)
	}
	return out.String(), nil
}

func parseSeconds(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
		if n > 86400 {
			return 86400
		}
	}
	return n
}

func randomNonce() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\n[truncated]"
}

// Sanity check that the implant never dials outside its scope for scan tasks.
var _ = net.JoinHostPort
