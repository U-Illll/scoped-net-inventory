// Command c2server runs the lab C2 server.
//
// It refuses to start unless -lab is passed, which is the operator's explicit
// acknowledgement of DISCLAIMER.md. Without it the process exits non-zero and
// prints the disclaimer path.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/U-Illll/scoped-net-inventory/c2/server"
)

func main() {
	var (
		listen     = flag.String("listen", "127.0.0.1:8443", "bind address (keep this on loopback or a lab network)")
		lab        = flag.Bool("lab", false, "acknowledge DISCLAIMER.md and enable research/lab mode (required)")
		secretFile = flag.String("secret-file", "", "file with the shared implant secret (>=16 bytes)")
		opToken    = flag.String("operator-token", "", "token for the operator API (or C2_OPERATOR_TOKEN)")
		sleep      = flag.Int("sleep", 5, "default beacon interval handed to implants, seconds")
		maxTasks   = flag.Int("max-tasks", 4, "max tasks handed out per beacon")
		genSecret  = flag.Bool("gen-secret", false, "print a fresh random secret and exit")
	)
	flag.Parse()

	if *genSecret {
		var b [32]byte
		if _, err := rand.Read(b[:]); err != nil {
			fmt.Fprintln(os.Stderr, "c2server: cannot read random:", err)
			os.Exit(1)
		}
		fmt.Println(hex.EncodeToString(b[:]))
		return
	}

	if !*lab {
		fmt.Fprintln(os.Stderr, "c2server: REFUSED — this is a research instrument and requires -lab.")
		fmt.Fprintln(os.Stderr, "c2server: read DISCLAIMER.md; do not point this at anything you do not own.")
		os.Exit(2)
	}

	secret, err := loadSecret(*secretFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "c2server:", err)
		os.Exit(3)
	}
	token := *opToken
	if token == "" {
		token = os.Getenv("C2_OPERATOR_TOKEN")
	}

	srv, err := server.New(server.Config{
		Listen:              *listen,
		Secret:              secret,
		OperatorToken:       token,
		Skew:                60 * time.Second,
		DefaultSleepSeconds: *sleep,
		MaxTasksPerBeacon:   *maxTasks,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "c2server:", err)
		os.Exit(4)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Fprintln(os.Stderr, "c2server: lab mode enabled — scope this to a container network you own")
	if err := srv.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "c2server:", err)
		os.Exit(5)
	}
}

func loadSecret(path string) ([]byte, error) {
	if path == "" {
		if v := os.Getenv("C2_SECRET"); v != "" {
			return []byte(v), nil
		}
		return nil, fmt.Errorf("a shared secret is required (-secret-file or C2_SECRET); generate one with -gen-secret")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading secret: %w", err)
	}
	s := trimSpace(string(raw))
	if len(s) < 16 {
		return nil, fmt.Errorf("secret in %s is shorter than 16 bytes", path)
	}
	return []byte(s), nil
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	for len(s) > 0 && (s[0] == '\n' || s[0] == '\r' || s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	return s
}
