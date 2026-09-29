package command

import (
	"context"
	"flag"
	"fmt"
	"github.com/grantlinehq/grantline/internal/collectors/spire"
	"github.com/grantlinehq/grantline/internal/config"
	"io"
	"os"
	"path/filepath"
)

func runExportSpire(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("export-spire", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("config", "", "single SPIRE local socket source config")
	out := flags.String("out", "", "private export file, or - for controlled stdout")
	if flags.Parse(args) != nil {
		return 2
	}
	if flags.NArg() != 0 || *path == "" || *out == "" {
		fmt.Fprintln(stderr, "grantline: export-spire requires --config and --out")
		return 2
	}
	cfg, err := config.Load(*path)
	if err != nil || len(cfg.Sources) != 1 || cfg.Sources[0].Kind != "spire" || cfg.Sources[0].Spire.SocketPath == "" || cfg.Sources[0].Spire.WorkloadEvidencePath != "" {
		fmt.Fprintln(stderr, "grantline: export-spire requires exactly one SPIRE local socket source")
		return 2
	}
	source := cfg.Sources[0].SpireConfig()
	s, err := (spire.Collector{Config: source}).Collect(context.Background())
	if err != nil {
		fmt.Fprintln(stderr, "grantline: invalid SPIRE collection metadata")
		return 2
	}
	data, err := spire.EncodeExport(source, s)
	if err != nil {
		fmt.Fprintln(stderr, "grantline: unable to encode SPIRE metadata export")
		return 2
	}
	if *out == "-" {
		_, err = stdout.Write(data)
	} else {
		err = writeSpireExport(*out, data)
	}
	if err != nil {
		fmt.Fprintln(stderr, "grantline: unable to write SPIRE metadata export")
		return 2
	}
	if hasIncompleteSources(s) {
		fmt.Fprintln(stderr, "grantline: export written with incomplete source coverage")
		return 2
	}
	return 0
}
func writeSpireExport(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".grantline-spire-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err = file.Chmod(0600); err != nil {
		return err
	}
	if _, err = file.Write(data); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
