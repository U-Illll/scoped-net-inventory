// Command netinv performs an authorised, bounded TCP reachability inventory.
//
// It refuses to run without a scope file, refuses any target outside that
// scope, caps concurrency and host count, and writes a JSON report. It does not
// fingerprint, send payloads, or take any action after a connection succeeds.
//
// Usage:
//
//	netinv -scope scope.json -out report.json [-timeout 1500ms] [-concurrency 8]
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/U-Illll/scoped-net-inventory/probe"
	"github.com/U-Illll/scoped-net-inventory/scope"
)

func main() {
	var (
		scopePath   = flag.String("scope", "", "scope authorisation file (required)")
		outPath     = flag.String("out", "-", "report path ('-' for stdout)")
		timeout     = flag.Duration("timeout", probe.DefaultTimeout, "per-connection timeout")
		concurrency = flag.Int("concurrency", probe.DefaultConcurrency, "parallel connect workers")
		expand      = flag.Bool("expand", false, "expand CIDR networks into host addresses")
		maxHosts    = flag.Int("max-hosts", probe.DefaultMaxHosts, "refuse a scope larger than this")
		printOnly   = flag.Bool("print-scope", false, "print the compiled scope and exit")
	)
	flag.Parse()

	if *scopePath == "" {
		fail("a scope file is required (-scope); this tool has no scan-everything mode")
	}
	sc, err := scope.Load(*scopePath)
	if err != nil {
		fail("%v", err)
	}
	if *printOnly {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(sc.Summary())
		return
	}

	hosts, err := resolveTargets(sc, *expand, *maxHosts)
	if err != nil {
		fail("%v", err)
	}
	if len(hosts) == 0 {
		fail("scope resolved to zero hosts")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	start := time.Now()
	results := probe.Run(ctx, hosts, sc.Ports(), probe.Options{
		Timeout: *timeout, Concurrency: *concurrency, MaxHosts: *maxHosts,
	})

	open := 0
	for _, r := range results {
		if r.Open {
			open++
		}
	}
	report := map[string]any{
		"generated_at":  time.Now().UTC().Format(time.RFC3339),
		"scope":         sc.Summary(),
		"hosts_scanned": len(hosts),
		"ports_scanned": len(sc.Ports()),
		"open_count":    open,
		"elapsed_ms":    time.Since(start).Milliseconds(),
		"results":       results,
	}
	if err := writeReport(*outPath, report); err != nil {
		fail("writing report: %v", err)
	}
	fmt.Fprintf(os.Stderr, "scanned %d hosts x %d ports: %d open in %s\n",
		len(hosts), len(sc.Ports()), open, time.Since(start).Round(time.Millisecond))
}

// resolveTargets turns the authorised scope into concrete hostnames/IPs.
// Without -expand, a CIDR contributes only its network and broadcast-style
// endpoints are never guessed; the caller is expected to enumerate.
func resolveTargets(sc *scope.Scope, expand bool, maxHosts int) ([]string, error) {
	summary := sc.Summary()
	hosts := make([]string, 0)
	for _, h := range summary["hosts"].([]string) {
		hosts = append(hosts, h)
	}
	if expand {
		for _, c := range summary["networks"].([]string) {
			ips, err := hostsInCIDR(c, maxHosts-len(hosts))
			if err != nil {
				return nil, err
			}
			hosts = append(hosts, ips...)
		}
	}
	sort.Strings(hosts)
	// Deduplicate while preserving determinism.
	uniq := hosts[:0]
	seen := map[string]bool{}
	for _, h := range hosts {
		if seen[h] {
			continue
		}
		seen[h] = true
		uniq = append(uniq, h)
	}
	for _, h := range uniq {
		if !sc.Allows(h) {
			return nil, fmt.Errorf("refusing out-of-scope target %q", h)
		}
	}
	if len(uniq) > maxHosts {
		return nil, fmt.Errorf("scope expands to %d hosts, above the %d limit", len(uniq), maxHosts)
	}
	return uniq, nil
}

// hostsInCIDR enumerates usable addresses in a prefix, bounded by limit.
func hostsInCIDR(cidr string, limit int) ([]string, error) {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	ones, bits := network.Mask.Size()
	capacity := 1 << (bits - ones)
	if bits-ones >= 16 || capacity > limit+2 {
		return nil, fmt.Errorf("network %s is too large to expand (limit %d hosts); list hosts explicitly or narrow the prefix", cidr, limit)
	}
	out := make([]string, 0, capacity)
	for cur := ip.Mask(network.Mask); network.Contains(cur); inc(cur) {
		// /31 and /32 have no network/broadcast reservation: every address
		// in them is usable.
		if ones <= bits-2 && (cur.Equal(network.IP) || isBroadcast(cur, network)) {
			continue
		}
		out = append(out, cur.String())
		if len(out) > limit {
			return nil, fmt.Errorf("network %s exceeds the %d host limit", cidr, limit)
		}
	}
	return out, nil
}

func inc(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return
		}
	}
}

func isBroadcast(ip net.IP, n *net.IPNet) bool {
	bcast := make(net.IP, len(n.IP))
	for i := range n.IP {
		bcast[i] = n.IP[i] | ^n.Mask[i]
	}
	return ip.Equal(bcast)
}

func writeReport(path string, report map[string]any) error {
	enc, closer, err := openWriter(path)
	if err != nil {
		return err
	}
	defer closer()
	e := json.NewEncoder(enc)
	e.SetIndent("", "  ")
	return e.Encode(report)
}

func openWriter(path string) (*os.File, func(), error) {
	if path == "" || path == "-" {
		return os.Stdout, func() {}, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { f.Close() }, nil
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "netinv: "+format+"\n", args...)
	os.Exit(2)
}
