// Package probe performs bounded TCP connectivity checks against targets that
// the scope already authorised.
//
// It opens a TCP connection, records whether the handshake completed and how
// long it took, and closes immediately. It does not send payloads, read
// banners, negotiate protocols, or attempt authentication.
package probe

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// Result is one host/port observation.
type Result struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Open    bool   `json:"open"`
	Millis  int64  `json:"ms"`
	Error   string `json:"error,omitempty"`
}

// Options configure the scan.
type Options struct {
	Timeout     time.Duration
	Concurrency int
	// MaxHosts caps the fan-out; a scope that expands beyond it is refused
	// rather than silently truncated.
	MaxHosts int
}

// Defaults keep a demonstration scan small and polite.
const (
	DefaultTimeout     = 1500 * time.Millisecond
	DefaultConcurrency = 8
	DefaultMaxHosts    = 256
	MaxConcurrency     = 32
)

// Targets expands the scope into concrete host/port pairs, refusing anything
// larger than MaxHosts so a typo in a CIDR cannot become a wide sweep.
func Targets(hosts []string, ports []int, maxHosts int) ([][2]any, error) {
	if maxHosts <= 0 {
		maxHosts = DefaultMaxHosts
	}
	if len(hosts) > maxHosts {
		return nil, fmt.Errorf("target set has %d hosts, above the %d limit", len(hosts), maxHosts)
	}
	out := make([][2]any, 0, len(hosts)*len(ports))
	for _, h := range hosts {
		for _, p := range ports {
			out = append(out, [2]any{h, p})
		}
	}
	return out, nil
}

// Run probes every host/port pair with bounded concurrency.
func Run(ctx context.Context, hosts []string, ports []int, opts Options) []Result {
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = DefaultConcurrency
	}
	if opts.Concurrency > MaxConcurrency {
		opts.Concurrency = MaxConcurrency
	}

	type job struct {
		host string
		port int
	}
	jobs := make(chan job)
	results := make([]Result, 0, len(hosts)*len(ports))
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dialer := &net.Dialer{Timeout: opts.Timeout}
			for j := range jobs {
				addr := net.JoinHostPort(j.host, fmt.Sprint(j.port))
				start := time.Now()
				conn, err := dialer.DialContext(ctx, "tcp", addr)
				r := Result{Host: j.host, Port: j.port, Millis: time.Since(start).Milliseconds()}
				if err != nil {
					r.Error = err.Error()
				} else {
					r.Open = true
					_ = conn.Close()
				}
				mu.Lock()
				results = append(results, r)
				mu.Unlock()
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, h := range hosts {
			for _, p := range ports {
				select {
				case jobs <- job{h, p}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	wg.Wait()

	sort.Slice(results, func(i, j int) bool {
		if results[i].Host != results[j].Host {
			return results[i].Host < results[j].Host
		}
		return results[i].Port < results[j].Port
	})
	return results
}
