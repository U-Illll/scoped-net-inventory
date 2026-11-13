package implant

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/U-Illll/scoped-net-inventory/c2/proto"
)

var testSecret = []byte("0123456789abcdef0123456789abcdef")

func writeScope(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "scope.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func newImplant(t *testing.T, extra func(*Config)) *implant {
	t.Helper()
	scopePath := writeScope(t, `{"hosts":["mock-asset"],"ports":[8080,8081]}`)
	cfg := Config{
		ServerURL:    "http://127.0.0.1:1",
		ImplantID:    "lab-1",
		Secret:       testSecret,
		ScopePath:    scopePath,
		MaxOutputLen: 1024,
	}
	if extra != nil {
		extra(&cfg)
	}
	im, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return im
}

func TestNewRejectsShortSecret(t *testing.T) {
	if _, err := New(Config{ServerURL: "http://x", Secret: []byte("short")}); err == nil {
		t.Fatal("short secret accepted")
	}
	if _, err := New(Config{ServerURL: "", Secret: testSecret}); err == nil {
		t.Fatal("missing server url accepted")
	}
}

func TestNewRejectsMissingScopeFile(t *testing.T) {
	_, err := New(Config{ServerURL: "http://x", Secret: testSecret, ScopePath: "/nonexistent/scope.json"})
	if err == nil {
		t.Fatal("nonexistent scope file accepted")
	}
}

func TestUnknownKindRefused(t *testing.T) {
	im := newImplant(t, nil)
	for _, kind := range []string{"shell", "download", "persist", "", "PING"} {
		res := im.execute(context.Background(), proto.Task{ID: "t", Kind: kind})
		if res.OK {
			t.Fatalf("kind %q executed successfully", kind)
		}
		if !strings.Contains(res.Error, "not allowlisted") {
			t.Fatalf("kind %q gave unexpected error %q", kind, res.Error)
		}
	}
}

func TestPingAndSysinfo(t *testing.T) {
	im := newImplant(t, nil)
	if res := im.execute(context.Background(), proto.Task{ID: "t", Kind: proto.KindPing}); !res.OK || res.Output != "pong" {
		t.Fatalf("ping failed: %+v", res)
	}
	res := im.execute(context.Background(), proto.Task{ID: "t", Kind: proto.KindSysinfo})
	if !res.OK || !strings.Contains(res.Output, "version=") {
		t.Fatalf("sysinfo failed: %+v", res)
	}
}

func TestScanRefusesOutOfScopeHost(t *testing.T) {
	im := newImplant(t, nil)
	res := im.execute(context.Background(), proto.Task{
		ID: "t", Kind: proto.KindScan,
		Args: map[string]string{"hosts": "10.0.0.1"},
	})
	if res.OK {
		t.Fatal("out-of-scope scan executed")
	}
	if !strings.Contains(res.Error, "out-of-scope") {
		t.Fatalf("unexpected error: %q", res.Error)
	}
}

func TestScanRefusesWhenNoScopeConfigured(t *testing.T) {
	im := newImplant(t, func(c *Config) { c.ScopePath = "" })
	// New() without a scope file is allowed (scope is optional at construction
	// time), but the scan task must then be refused outright.
	res := im.execute(context.Background(), proto.Task{
		ID: "t", Kind: proto.KindScan,
		Args: map[string]string{"hosts": "mock-asset"},
	})
	if res.OK {
		t.Fatal("scan ran without a configured scope")
	}
	if !strings.Contains(res.Error, "no scope file") {
		t.Fatalf("unexpected error: %q", res.Error)
	}
}

func TestScanInScopeHostSucceeds(t *testing.T) {
	im := newImplant(t, nil)
	// A short timeout keeps the test fast; closed ports just report false.
	res := im.execute(context.Background(), proto.Task{
		ID: "t", Kind: proto.KindScan,
		Args: map[string]string{"hosts": "mock-asset"},
	})
	if !res.OK {
		t.Fatalf("in-scope scan refused: %+v", res)
	}
	if !strings.Contains(res.Output, "total_hosts=1") {
		t.Fatalf("unexpected scan output: %q", res.Output)
	}
}

func TestExecRefusedWithoutAllowlist(t *testing.T) {
	im := newImplant(t, nil)
	res := im.execute(context.Background(), proto.Task{
		ID: "t", Kind: proto.KindExec,
		Args: map[string]string{"argv": "/bin/echo hi"},
	})
	if res.OK {
		t.Fatal("exec ran with an empty allowlist")
	}
	if !strings.Contains(res.Error, "allowlist") {
		t.Fatalf("unexpected error: %q", res.Error)
	}
}

func TestExecRefusesRelativePath(t *testing.T) {
	im := newImplant(t, func(c *Config) { c.ExecAllow = []string{"/bin/echo"} })
	res := im.execute(context.Background(), proto.Task{
		ID: "t", Kind: proto.KindExec,
		Args: map[string]string{"argv": "echo hi"},
	})
	if res.OK {
		t.Fatal("relative path executed")
	}
	if !strings.Contains(res.Error, "absolute path") {
		t.Fatalf("unexpected error: %q", res.Error)
	}
}

func TestExecRefusesNonAllowlistedBinary(t *testing.T) {
	im := newImplant(t, func(c *Config) { c.ExecAllow = []string{"/bin/echo"} })
	res := im.execute(context.Background(), proto.Task{
		ID: "t", Kind: proto.KindExec,
		Args: map[string]string{"argv": "/bin/sh -c id"},
	})
	if res.OK {
		t.Fatal("non-allowlisted binary executed")
	}
	if !strings.Contains(res.Error, "not in the exec allowlist") {
		t.Fatalf("unexpected error: %q", res.Error)
	}
}

func TestExecAllowlistedBinaryRuns(t *testing.T) {
	if _, err := os.Stat("/bin/echo"); err != nil {
		t.Skip("/bin/echo unavailable")
	}
	im := newImplant(t, func(c *Config) { c.ExecAllow = []string{"/bin/echo"} })
	res := im.execute(context.Background(), proto.Task{
		ID: "t", Kind: proto.KindExec,
		Args: map[string]string{"argv": "/bin/echo hello-lab"},
	})
	if !res.OK {
		t.Fatalf("allowlisted exec failed: %+v", res)
	}
	if !strings.Contains(res.Output, "hello-lab") {
		t.Fatalf("unexpected output: %q", res.Output)
	}
}

func TestSleepAndExitAreNoOps(t *testing.T) {
	im := newImplant(t, nil)
	for _, kind := range []string{proto.KindSleep, proto.KindExit} {
		res := im.execute(context.Background(), proto.Task{ID: "t", Kind: kind})
		if !res.OK {
			t.Fatalf("%s failed: %+v", kind, res)
		}
	}
}

func TestParseSeconds(t *testing.T) {
	cases := map[string]int{"": 0, "30": 30, "0": 0, "abc": 0, "-5": 0, "999999": 86400}
	for in, want := range cases {
		if got := parseSeconds(in); got != want {
			t.Fatalf("parseSeconds(%q)=%d want %d", in, got, want)
		}
	}
}

func TestTruncate(t *testing.T) {
	if truncate("short", 10) != "short" {
		t.Fatal("short string truncated")
	}
	if !strings.Contains(truncate("0123456789abcdef", 4), "[truncated]") {
		t.Fatal("long string not marked truncated")
	}
}
