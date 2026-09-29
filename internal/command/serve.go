package command

import (
	"context"
	"flag"
	"fmt"
	"github.com/grantlinehq/grantline/internal/viewer"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"time"
)

func runServe(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(stderr)
	reportPath := flags.String("report", "", "path to a self-contained report")
	listen := flags.String("listen", "127.0.0.1:8080", "literal IPv4 loopback address")
	accessDir := flags.String("access-dir", "", "directory for the private temporary access-code file (defaults to report directory)")
	if flags.Parse(arguments) != nil || flags.NArg() != 0 || *reportPath == "" {
		fmt.Fprintln(stderr, "grantline: serve requires --report and accepts no positional arguments")
		return 2
	}
	if err := viewer.Address(*listen); err != nil {
		fmt.Fprintln(stderr, "grantline:", err)
		return 2
	}
	report, err := viewer.Load(*reportPath)
	if err != nil {
		fmt.Fprintln(stderr, "grantline:", err)
		return 2
	}
	token, err := viewer.Token()
	if err != nil {
		fmt.Fprintln(stderr, "grantline: cannot generate access code")
		return 2
	}
	handler, err := viewer.New(report, *listen, token)
	if err != nil {
		fmt.Fprintln(stderr, "grantline:", err)
		return 2
	}
	listener, err := net.Listen("tcp4", *listen)
	if err != nil {
		fmt.Fprintln(stderr, "grantline: local viewer port unavailable")
		return 2
	}
	defer listener.Close()
	dir := *accessDir
	if dir == "" {
		dir = filepath.Dir(*reportPath)
	}
	file, err := os.CreateTemp(dir, ".viewer-access-*")
	if err != nil {
		fmt.Fprintln(stderr, "grantline: cannot create private access-code file")
		return 2
	}
	defer os.Remove(file.Name())
	if _, err = file.WriteString(token + "\n"); err != nil {
		file.Close()
		fmt.Fprintln(stderr, "grantline: cannot write access-code file")
		return 2
	}
	if err = file.Close(); err != nil {
		return 2
	}
	path, _ := filepath.Abs(file.Name())
	fmt.Fprintf(stdout, "Grantline viewer: http://%s\nAccess code file: %s\nRead the private file locally and paste its code into the viewer. The code expires when this process stops.\n", *listen, path)
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 8 << 10}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			server.Shutdown(shutdown)
		case <-done:
		}
	}()
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(stderr, "grantline: viewer stopped unexpectedly")
		return 2
	}
	return 0
}
