// Package scope enforces which targets a scan may touch.
//
// A scope file lists the networks an operator is authorised to inventory. Every
// target must match one of those entries; there is no allow-all mode and no
// flag that widens the scope at runtime. Anything outside the file is refused
// before a socket is opened.
package scope

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

// File is the on-disk scope document.
type File struct {
	// Networks are CIDR blocks the operator is authorised to inventory.
	Networks []string `json:"networks"`
	// Hosts are individual hostnames or IPs, express or implied.
	Hosts []string `json:"hosts"`
	// Ports limits the scan to these ports. Empty means the default set.
	Ports []int `json:"ports"`
	// Note records why this scope exists (ticket id, owner confirmation).
	Note string `json:"note,omitempty"`
}

// Scope is a compiled, queryable authorisation list.
type Scope struct {
	nets   []*net.IPNet
	hosts  map[string]bool
	ports  map[int]bool
	Source string
}

// DefaultPorts is a small, common service set. It is intentionally narrow: an
// inventory does not need the full 65k range, and a smaller set is easier to
// justify and to rate-limit.
var DefaultPorts = []int{22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9000}

// Load reads and validates a scope file.
func Load(path string) (*Scope, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read scope: %w", err)
	}
	var f File
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("parse scope: %w", err)
	}
	return Compile(&f, path)
}

// Compile turns a parsed file into a Scope. An empty scope is an error: a scan
// with nothing authorised must fail closed rather than scan everything.
func Compile(f *File, source string) (*Scope, error) {
	s := &Scope{hosts: map[string]bool{}, ports: map[int]bool{}, Source: source}
	for _, c := range f.Networks {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("bad network %q: %w", c, err)
		}
		s.nets = append(s.nets, n)
	}
	for _, h := range f.Hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		s.hosts[strings.ToLower(h)] = true
	}
	if len(s.nets) == 0 && len(s.hosts) == 0 {
		return nil, fmt.Errorf("scope is empty: nothing is authorised, refusing to scan")
	}
	ports := f.Ports
	if len(ports) == 0 {
		ports = DefaultPorts
	}
	for _, p := range ports {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("bad port %d", p)
		}
		s.ports[p] = true
	}
	if len(s.ports) == 0 {
		return nil, fmt.Errorf("no ports configured")
	}
	return s, nil
}

// Ports returns the authorised ports in configured order.
func (s *Scope) Ports() []int {
	out := make([]int, 0, len(s.ports))
	for p := range s.ports {
		out = append(out, p)
	}
	// stable order for reproducible reports
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// Allows reports whether a host is inside the authorised scope.
func (s *Scope) Allows(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	if s.hosts[host] {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// Try resolving only for name entries, never to widen the scope.
		for name := range s.hosts {
			if net.ParseIP(name) != nil {
				continue
			}
			addrs, err := net.LookupHost(name)
			if err != nil {
				continue
			}
			if strings.EqualFold(name, host) {
				_ = addrs
			}
		}
		return s.hosts[host]
	}
	for _, n := range s.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Summary describes the compiled scope for the report header.
func (s *Scope) Summary() map[string]any {
	nets := make([]string, 0, len(s.nets))
	for _, n := range s.nets {
		nets = append(nets, n.String())
	}
	hosts := make([]string, 0, len(s.hosts))
	for h := range s.hosts {
		hosts = append(hosts, h)
	}
	return map[string]any{
		"networks": nets,
		"hosts":    hosts,
		"ports":    s.Ports(),
		"source":   s.Source,
	}
}
