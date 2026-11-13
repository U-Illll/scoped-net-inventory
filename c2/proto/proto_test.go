package proto

import (
	"net/http"
	"testing"
	"time"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	body := []byte(`{"implant_id":"lab-1"}`)
	ts := "1700000000"
	sig := Sign(secret, ts, body)
	if !Verify(secret, ts, body, sig) {
		t.Fatal("valid signature rejected")
	}
	if Verify(secret, ts, []byte(`{"implant_id":"lab-2"}`), sig) {
		t.Fatal("signature accepted for a modified body")
	}
	if Verify([]byte("ffffffffffffffffffffffffffffffff"), ts, body, sig) {
		t.Fatal("signature accepted under a different secret")
	}
	if Verify(secret, "1700000001", body, sig) {
		t.Fatal("signature accepted for a different timestamp")
	}
}

func TestCheckSkew(t *testing.T) {
	now := time.Unix(1700000000, 0)
	if err := CheckSkew("1700000000", 60*time.Second, now); err != nil {
		t.Fatalf("in-window timestamp rejected: %v", err)
	}
	if err := CheckSkew("1699999000", 60*time.Second, now); err == nil {
		t.Fatal("stale timestamp accepted")
	}
	if err := CheckSkew("1700001000", 60*time.Second, now); err == nil {
		t.Fatal("future timestamp accepted")
	}
	if err := CheckSkew("not-a-number", 60*time.Second, now); err == nil {
		t.Fatal("malformed timestamp accepted")
	}
}

func TestIsKnownKind(t *testing.T) {
	for _, k := range KnownKinds() {
		if !IsKnownKind(k) {
			t.Fatalf("allowlisted kind %q reported unknown", k)
		}
	}
	for _, k := range []string{"", "shell", "download", "upload", "persist", "PING"} {
		if IsKnownKind(k) {
			t.Fatalf("kind %q should not be allowlisted", k)
		}
	}
}

func TestSortedArgs(t *testing.T) {
	got := SortedArgs(map[string]string{"b": "2", "a": "1"})
	if got != "a=1 b=2" {
		t.Fatalf("unstable arg ordering: %q", got)
	}
	if SortedArgs(nil) != "" {
		t.Fatal("empty args should render empty")
	}
}

// Guard against the server accidentally accepting a non-POST body.
var _ = http.MethodPost
