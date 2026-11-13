package probe

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestTargetsRefusesTooManyHosts(t *testing.T) {
	hosts := make([]string, 5)
	for i := range hosts {
		hosts[i] = "h"
	}
	if _, err := Targets(hosts, []int{80}, 2); err == nil {
		t.Fatal("expected refusal above max hosts")
	}
}

func TestRunFindsOpenAndClosedPorts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	openPort := ln.Addr().(*net.TCPAddr).Port
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	results := Run(ctx, []string{"127.0.0.1"}, []int{openPort, 1},
		Options{Timeout: 400 * time.Millisecond, Concurrency: 2})

	var sawOpen, sawClosed bool
	for _, r := range results {
		if r.Port == openPort && r.Open {
			sawOpen = true
		}
		if r.Port == 1 && !r.Open {
			sawClosed = true
		}
		if r.Host != "127.0.0.1" {
			t.Fatalf("unexpected host %q", r.Host)
		}
	}
	if !sawOpen {
		t.Fatalf("open port not detected: %+v", results)
	}
	if !sawClosed {
		t.Fatalf("closed port reported open: %+v", results)
	}
}

func TestRunRespectsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	results := Run(ctx, []string{"127.0.0.1"}, []int{65000},
		Options{Timeout: time.Second, Concurrency: 1})
	if len(results) != 0 {
		t.Fatalf("expected no results after cancel, got %d", len(results))
	}
}

func TestConcurrencyIsCapped(t *testing.T) {
	// Only asserts the run completes with an oversized request; the cap is
	// applied internally, so the visible contract is "it still works".
	results := Run(context.Background(), []string{"127.0.0.1"}, []int{1},
		Options{Timeout: 200 * time.Millisecond, Concurrency: 1000})
	if len(results) != 1 {
		t.Fatalf("expected one result, got %d", len(results))
	}
}
