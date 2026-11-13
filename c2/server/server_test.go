package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/U-Illll/scoped-net-inventory/c2/proto"
)

var testSecret = []byte("0123456789abcdef0123456789abcdef")

func newTestServer(t *testing.T) *Server {
	t.Helper()
	s, err := New(Config{
		Listen:              "127.0.0.1:0",
		Secret:              testSecret,
		OperatorToken:       "op-token",
		Skew:                time.Minute,
		DefaultSleepSeconds: 1,
		MaxTasksPerBeacon:   2,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func signedRequest(t *testing.T, method, path string, body []byte) *http.Request {
	t.Helper()
	ts := fmt.Sprintf("%d", time.Now().Unix())
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("X-C2-Timestamp", ts)
	req.Header.Set("X-C2-Signature", proto.Sign(testSecret, ts, body))
	return req
}

func beaconBody(id string) []byte {
	b, _ := json.Marshal(proto.Beacon{ImplantID: id, Hostname: "lab", OS: "linux", Arch: "amd64", Version: proto.Version})
	return b
}

func TestNewRejectsWeakConfig(t *testing.T) {
	if _, err := New(Config{Secret: []byte("short"), OperatorToken: "x"}); err == nil {
		t.Fatal("short secret accepted")
	}
	if _, err := New(Config{Secret: testSecret}); err == nil {
		t.Fatal("missing operator token accepted")
	}
}

func TestBeaconRequiresSignature(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/implant/beacon", bytes.NewReader(beaconBody("lab-1")))
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned beacon got %d, want 401", rr.Code)
	}
}

func TestBeaconRejectsBadSignature(t *testing.T) {
	s := newTestServer(t)
	ts := fmt.Sprintf("%d", time.Now().Unix())
	req := httptest.NewRequest(http.MethodPost, "/implant/beacon", bytes.NewReader(beaconBody("lab-1")))
	req.Header.Set("X-C2-Timestamp", ts)
	req.Header.Set("X-C2-Signature", "deadbeef")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("bad signature got %d, want 401", rr.Code)
	}
}

func TestBeaconRejectsStaleTimestamp(t *testing.T) {
	s := newTestServer(t)
	body := beaconBody("lab-1")
	ts := fmt.Sprintf("%d", time.Now().Add(-10*time.Minute).Unix())
	req := httptest.NewRequest(http.MethodPost, "/implant/beacon", bytes.NewReader(body))
	req.Header.Set("X-C2-Timestamp", ts)
	req.Header.Set("X-C2-Signature", proto.Sign(testSecret, ts, body))
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("stale beacon got %d, want 401", rr.Code)
	}
}

func TestBeaconRegistersImplant(t *testing.T) {
	s := newTestServer(t)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, signedRequest(t, http.MethodPost, "/implant/beacon", beaconBody("lab-1")))
	if rr.Code != http.StatusOK {
		t.Fatalf("beacon got %d: %s", rr.Code, rr.Body.String())
	}
	var reply proto.BeaconReply
	if err := json.Unmarshal(rr.Body.Bytes(), &reply); err != nil {
		t.Fatalf("decode reply: %v", err)
	}
	if reply.SleepSeconds != 1 {
		t.Fatalf("sleep=%d want 1", reply.SleepSeconds)
	}
	s.mu.Lock()
	_, ok := s.implants["lab-1"]
	s.mu.Unlock()
	if !ok {
		t.Fatal("implant was not registered")
	}
}

func TestOperatorAuthRequired(t *testing.T) {
	s := newTestServer(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/operator/implants", nil)
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("unauthenticated operator request got %d, want 403", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/operator/implants", nil)
	req.Header.Set("X-Operator-Token", "wrong")
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("wrong operator token got %d, want 403", rr.Code)
	}
}

func TestImplantSecretCannotReachOperatorAPI(t *testing.T) {
	s := newTestServer(t)
	// Register an implant first, then try the operator API using implant-style
	// signed headers only.
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, signedRequest(t, http.MethodPost, "/implant/beacon", beaconBody("lab-1")))

	body := []byte(`{}`)
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, signedRequest(t, http.MethodPost, "/operator/task", body))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("implant signature reached operator API with %d, want 403", rr.Code)
	}
}

func TestTaskRejectsUnknownKind(t *testing.T) {
	s := newTestServer(t)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, signedRequest(t, http.MethodPost, "/implant/beacon", beaconBody("lab-1")))

	for _, kind := range []string{"shell", "download", "persist", ""} {
		payload, _ := json.Marshal(map[string]any{"implant_id": "lab-1", "kind": kind})
		rr = httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/operator/task", bytes.NewReader(payload))
		req.Header.Set("X-Operator-Token", "op-token")
		s.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("kind %q got %d, want 400", kind, rr.Code)
		}
	}
}

func TestTaskDeliveredOnceAndCapped(t *testing.T) {
	s := newTestServer(t)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, signedRequest(t, http.MethodPost, "/implant/beacon", beaconBody("lab-1")))

	// Queue three tasks; MaxTasksPerBeacon is 2.
	for i := 0; i < 3; i++ {
		payload, _ := json.Marshal(map[string]any{"implant_id": "lab-1", "kind": proto.KindPing})
		req := httptest.NewRequest(http.MethodPost, "/operator/task", bytes.NewReader(payload))
		req.Header.Set("X-Operator-Token", "op-token")
		rr = httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("enqueue %d got %d: %s", i, rr.Code, rr.Body.String())
		}
	}

	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, signedRequest(t, http.MethodPost, "/implant/beacon", beaconBody("lab-1")))
	var first proto.BeaconReply
	_ = json.Unmarshal(rr.Body.Bytes(), &first)
	if len(first.Tasks) != 2 {
		t.Fatalf("first beacon delivered %d tasks, want 2 (cap)", len(first.Tasks))
	}

	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, signedRequest(t, http.MethodPost, "/implant/beacon", beaconBody("lab-1")))
	var second proto.BeaconReply
	_ = json.Unmarshal(rr.Body.Bytes(), &second)
	if len(second.Tasks) != 1 {
		t.Fatalf("second beacon delivered %d tasks, want the remaining 1", len(second.Tasks))
	}

	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, signedRequest(t, http.MethodPost, "/implant/beacon", beaconBody("lab-1")))
	var third proto.BeaconReply
	_ = json.Unmarshal(rr.Body.Bytes(), &third)
	if len(third.Tasks) != 0 {
		t.Fatalf("third beacon re-delivered %d tasks, want 0", len(third.Tasks))
	}
}

func TestTaskForUnknownImplant(t *testing.T) {
	s := newTestServer(t)
	payload, _ := json.Marshal(map[string]any{"implant_id": "ghost", "kind": proto.KindPing})
	req := httptest.NewRequest(http.MethodPost, "/operator/task", bytes.NewReader(payload))
	req.Header.Set("X-Operator-Token", "op-token")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("unknown implant got %d, want 404", rr.Code)
	}
}

func TestResultRecorded(t *testing.T) {
	s := newTestServer(t)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, signedRequest(t, http.MethodPost, "/implant/beacon", beaconBody("lab-1")))

	body, _ := json.Marshal(proto.Result{
		ImplantID: "lab-1", TaskID: "t1", Kind: proto.KindPing, OK: true, Output: "pong",
	})
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, signedRequest(t, http.MethodPost, "/implant/result", body))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("result got %d: %s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/operator/implants", nil)
	req.Header.Set("X-Operator-Token", "op-token")
	s.Handler().ServeHTTP(rr, req)
	if !strings.Contains(rr.Body.String(), "pong") {
		t.Fatalf("result not visible to operator: %s", rr.Body.String())
	}
}
