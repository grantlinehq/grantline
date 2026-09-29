package command

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/grantlinehq/grantline/internal/platform"
)

func runRotateKey(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("rotate-key", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("new-key-file", "", "private persisted file containing the new base64 key")
	if flags.Parse(arguments) != nil || flags.NArg() != 0 || *path == "" {
		return 2
	}
	cfg, e := serverConfig()
	if e != nil {
		fmt.Fprintln(stderr, "grantline: current configuration unavailable")
		return 2
	}
	b, e := os.ReadFile(*path)
	if e != nil || len(b) > 1024 {
		fmt.Fprintln(stderr, "grantline: new key file unavailable")
		return 2
	}
	key, e := base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if e != nil || len(key) != 32 {
		fmt.Fprintln(stderr, "grantline: new key must encode 32 random bytes without padding")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	db, e := platform.Open(ctx, cfg.DatabaseURL)
	if e != nil {
		fmt.Fprintln(stderr, "grantline: database unavailable")
		return 2
	}
	defer db.Close()
	if e = platform.RotateKey(ctx, db, cfg.EncryptionKey, key); e != nil {
		fmt.Fprintln(stderr, "grantline: key rotation failed; ensure server is stopped and key matches the database")
		return 2
	}
	fmt.Fprintln(stdout, "Database re-encryption committed. Configure the server to use the new key file before starting. Keep the old key with older backups. Existing sessions were revoked.")
	return 0
}
