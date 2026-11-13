// Command c2implant runs the lab implant against a local C2 server.
//
// It refuses to start without -lab (acknowledgement of DISCLAIMER.md) and
// without a scope file, because the only scanning it can be tasked to do is
// against hosts that file already authorises.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/U-Illll/scoped-net-inventory/c2/implant"
)

func main() {
	var (
		serverURL  = flag.String("server", "http://127.0.0.1:8443", "C2 server base URL")
		secretFile = flag.String("secret-file", "", "file with the shared secret (>=16 bytes)")
		scopePath  = flag.String("scope", "", "scope file limiting what a scan task may touch (required)")
		execAllow  = flag.String("exec-allow", "", "comma-separated absolute paths the exec task may run (empty disables exec)")
		id         = flag.String("id", "", "implant id (default derived from hostname)")
		lab        = flag.Bool("lab", false, "acknowledge DISCLAIMER.md and enable research/lab mode (required)")
	)
	flag.Parse()

	if !*lab {
		fmt.Fprintln(os.Stderr, "c2implant: REFUSED — this is a research instrument and requires -lab.")
		fmt.Fprintln(os.Stderr, "c2implant: read DISCLAIMER.md; run it only inside a container you own.")
		os.Exit(2)
	}
	if *scopePath == "" {
		fmt.Fprintln(os.Stderr, "c2implant: -scope is required; the implant will not run unrestricted")
		os.Exit(3)
	}

	secret, err := loadSecret(*secretFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "c2implant:", err)
		os.Exit(4)
	}

	var allow []string
	for _, p := range strings.Split(*execAllow, ",") {
		if p = strings.TrimSpace(p); p != "" {
			allow = append(allow, p)
		}
	}

	im, err := implant.New(implant.Config{
		ServerURL:   *serverURL,
		ImplantID:   *id,
		Secret:      secret,
		Skew:        60 * time.Second,
		HTTPTimeout: 15 * time.Second,
		ScopePath:   *scopePath,
		ExecAllow:   allow,
		ExecTimeout: 10 * time.Second,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "c2implant:", err)
		os.Exit(5)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Fprintln(os.Stderr, "c2implant: lab mode — beaconing to", *serverURL)
	if err := im.Run(ctx); err != nil && ctx.Err() == nil {
		fmt.Fprintln(os.Stderr, "c2implant:", err)
		os.Exit(6)
	}
}

func loadSecret(path string) ([]byte, error) {
	if path == "" {
		if v := os.Getenv("C2_SECRET"); v != "" {
			return []byte(v), nil
		}
		return nil, fmt.Errorf("a shared secret is required (-secret-file or C2_SECRET)")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading secret: %w", err)
	}
	s := strings.TrimSpace(string(raw))
	if len(s) < 16 {
		return nil, fmt.Errorf("secret in %s is shorter than 16 bytes", path)
	}
	return []byte(s), nil
}
