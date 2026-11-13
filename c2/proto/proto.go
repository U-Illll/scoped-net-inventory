// Package proto defines the wire format shared by the research C2 server and
// its implants.
//
// This module is a lab instrument, not an operational tool: the protocol is
// plain JSON over HTTP, every message is HMAC-signed with a shared secret, and
// there is no covert channel, no obfuscation and no fallback transport. See
// DISCLAIMER.md.
package proto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Version is the protocol version. Both sides refuse to talk across versions.
const Version = "1"

// Task kinds an implant will accept. Anything not listed here is rejected by
// the implant before any handler is reached, including kinds added to the
// server later.
const (
	KindPing    = "ping"
	KindSysinfo = "sysinfo"
	KindScan    = "scan"
	KindSleep   = "sleep"
	KindExit    = "exit"
	KindExec    = "exec"
)

// Beacon is sent by an implant on every check-in.
type Beacon struct {
	ImplantID string    `json:"implant_id"`
	Hostname  string    `json:"hostname"`
	OS        string    `json:"os"`
	Arch      string    `json:"arch"`
	Version   string    `json:"version"`
	Nonce     string    `json:"nonce"`
	SentAt    time.Time `json:"sent_at"`
}

// Task is one unit of work handed to an implant.
type Task struct {
	ID       string            `json:"id"`
	Kind     string            `json:"kind"`
	Args     map[string]string `json:"args,omitempty"`
	IssuedAt time.Time         `json:"issued_at"`
}

// BeaconReply tells the implant what to do next.
type BeaconReply struct {
	Tasks         []Task `json:"tasks"`
	SleepSeconds  int    `json:"sleep_seconds"`
	JitterPercent int    `json:"jitter_percent"`
}

// Result is an implant reporting on one task.
type Result struct {
	ImplantID  string    `json:"implant_id"`
	TaskID     string    `json:"task_id"`
	Kind       string    `json:"kind"`
	OK         bool      `json:"ok"`
	Output     string    `json:"output,omitempty"`
	Error      string    `json:"error,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	DurationMS int64     `json:"duration_ms"`
}

// KnownKinds reports whether a task kind is in the allowlist.
func KnownKinds() []string {
	return []string{KindPing, KindSysinfo, KindScan, KindSleep, KindExit, KindExec}
}

// IsKnownKind reports whether kind is an allowlisted task kind.
func IsKnownKind(kind string) bool {
	switch kind {
	case KindPing, KindSysinfo, KindScan, KindSleep, KindExit, KindExec:
		return true
	}
	return false
}

// Sign returns the hex HMAC-SHA256 of body under secret.
//
// The timestamp is part of the signed material so a captured request cannot be
// replayed later without also rewriting the header, which the verifier rejects
// outside the skew window.
func Sign(secret []byte, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(timestamp))
	mac.Write([]byte("\n"))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify checks a signature in constant time.
func Verify(secret []byte, timestamp string, body []byte, signature string) bool {
	want := Sign(secret, timestamp, body)
	return hmac.Equal([]byte(want), []byte(signature))
}

// CheckSkew rejects timestamps outside the allowed window.
func CheckSkew(timestamp string, window time.Duration, now time.Time) error {
	ts, err := strconv.ParseInt(strings.TrimSpace(timestamp), 10, 64)
	if err != nil {
		return fmt.Errorf("bad timestamp %q", timestamp)
	}
	at := time.Unix(ts, 0)
	if d := now.Sub(at); d > window || d < -window {
		return fmt.Errorf("timestamp outside %s window", window)
	}
	return nil
}

// SortedArgs returns task args as "k=v" pairs in stable order, for logging.
func SortedArgs(args map[string]string) string {
	if len(args) == 0 {
		return ""
	}
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+args[k])
	}
	return strings.Join(parts, " ")
}
