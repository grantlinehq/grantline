package command

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"github.com/grantlinehq/grantline/internal/platform"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func envFile(name string) (string, error) {
	if file := os.Getenv(name + "_FILE"); file != "" {
		b, e := os.ReadFile(file)
		if e != nil || len(b) > 1<<20 {
			return "", errors.New("configuration secret file unavailable")
		}
		return strings.TrimSpace(string(b)), nil
	}
	return os.Getenv(name), nil
}
func serverConfig() (platform.Config, error) {
	var cfg platform.Config
	cfg.Version = Version
	var e error
	cfg.PublicURL = os.Getenv("GRANTLINE_PUBLIC_URL")
	if cfg.PublicURL == "" {
		cfg.PublicURL = "http://127.0.0.1:8080"
	}
	cfg.DatabaseURL, e = envFile("GRANTLINE_DATABASE_URL")
	if e != nil {
		return cfg, e
	}
	key, e := envFile("GRANTLINE_ENCRYPTION_KEY")
	if e != nil {
		return cfg, e
	}
	cfg.EncryptionKey, e = base64.RawStdEncoding.DecodeString(key)
	if e != nil || len(cfg.EncryptionKey) != 32 {
		return cfg, errors.New("encryption key file must contain a base64-encoded 32-byte key")
	}
	cfg.SetupToken, e = envFile("GRANTLINE_SETUP_TOKEN")
	if e != nil {
		return cfg, e
	}
	cfg.SecretDir = os.Getenv("GRANTLINE_SECRET_DIR")
	cfg.CustomCA = os.Getenv("GRANTLINE_CA_FILE")
	for _, value := range strings.Split(os.Getenv("GRANTLINE_TRUSTED_PROXIES"), ",") {
		if strings.TrimSpace(value) == "" {
			continue
		}
		p, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			return cfg, errors.New("trusted proxies must be explicit IP CIDRs")
		}
		cfg.TrustedProxies = append(cfg.TrustedProxies, p)
	}
	cfg.OIDCIssuer = os.Getenv("GRANTLINE_OIDC_ISSUER")
	cfg.OIDCClientID = os.Getenv("GRANTLINE_OIDC_CLIENT_ID")
	cfg.OIDCClientSecret, e = envFile("GRANTLINE_OIDC_CLIENT_SECRET")
	if e != nil {
		return cfg, e
	}
	cfg.SMTPAddress = os.Getenv("GRANTLINE_SMTP_ADDRESS")
	cfg.SMTPUsername = os.Getenv("GRANTLINE_SMTP_USERNAME")
	cfg.SMTPFrom = os.Getenv("GRANTLINE_SMTP_FROM")
	cfg.SMTPPassword, e = envFile("GRANTLINE_SMTP_PASSWORD")
	return cfg, e
}
func runServer(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("server", flag.ContinueOnError)
	flags.SetOutput(stderr)
	listen := flags.String("listen", "127.0.0.1:8080", "HTTP listen address; configure public HTTPS URL behind a reverse proxy")
	if flags.Parse(arguments) != nil || flags.NArg() != 0 {
		return 2
	}
	cfg, e := serverConfig()
	if e != nil {
		fmt.Fprintln(stderr, "grantline:", e)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	dbCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	db, e := platform.Open(dbCtx, cfg.DatabaseURL)
	cancel()
	if e != nil {
		fmt.Fprintln(stderr, "grantline: database unavailable")
		return 2
	}
	defer db.Close()
	handler, e := platform.New(db, cfg)
	if e != nil {
		fmt.Fprintln(stderr, "grantline:", e)
		return 2
	}
	workerCtx, endWorker := context.WithCancel(ctx)
	defer endWorker()
	done, e := handler.StartWorker(workerCtx)
	if e != nil {
		fmt.Fprintln(stderr, "grantline: worker unavailable; run migrate and check for another instance")
		return 2
	}
	server := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 120 * time.Second, WriteTimeout: 180 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() {
		select {
		case <-ctx.Done():
		case <-done:
			stop()
		}
		shutdown, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		server.Shutdown(shutdown)
	}()
	fmt.Fprintln(stdout, "Grantline server:", cfg.PublicURL)
	e = server.ListenAndServe()
	endWorker()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
	}
	if e != nil && e != http.ErrServerClosed {
		fmt.Fprintln(stderr, "grantline: server stopped unexpectedly")
		return 2
	}
	return 0
}
func runMigrate(arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) != 0 {
		return 2
	}
	value, e := envFile("GRANTLINE_DATABASE_URL")
	if e != nil {
		fmt.Fprintln(stderr, "grantline: database configuration unavailable")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for {
		db, e := platform.Open(ctx, value)
		if e == nil {
			e = platform.Migrate(ctx, db)
			db.Close()
			if e != nil {
				fmt.Fprintln(stderr, "grantline: migration failed; database left unchanged")
				return 2
			}
			fmt.Fprintln(stdout, "Database migration complete.")
			return 0
		}
		select {
		case <-ctx.Done():
			fmt.Fprintln(stderr, "grantline: database unavailable")
			return 2
		case <-time.After(2 * time.Second):
		}
	}
}
func runInit(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dir := flags.String("secrets-dir", "", "private persistent secret directory")
	databaseDir := flags.String("database-secrets-dir", "", "optional isolated directory containing only the PostgreSQL password")
	host := flags.String("database-host", "postgres", "database host")
	if flags.Parse(arguments) != nil || flags.NArg() != 0 || *dir == "" || strings.ContainsAny(*host, "/\\@:? \r\n") {
		return 2
	}
	if os.MkdirAll(*dir, 0700) != nil {
		return 2
	}
	create := func(name string, n int) (string, error) {
		path := filepath.Join(*dir, name)
		b, e := os.ReadFile(path)
		if e == nil {
			return strings.TrimSpace(string(b)), nil
		}
		if !os.IsNotExist(e) {
			return "", e
		}
		b = make([]byte, n)
		if _, e = rand.Read(b); e != nil {
			return "", e
		}
		value := base64.RawURLEncoding.EncodeToString(b)
		if name == "encryption-key" {
			value = base64.RawStdEncoding.EncodeToString(b)
		}
		f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return "", e
		}
		_, e = f.WriteString(value + "\n")
		closeErr := f.Close()
		if e != nil {
			return "", e
		}
		return value, closeErr
	}
	password, e := create("postgres-password", 32)
	if e != nil {
		return 2
	}
	if *databaseDir != "" {
		if os.MkdirAll(*databaseDir, 0755) != nil {
			return 2
		}
		file := filepath.Join(*databaseDir, "postgres-password")
		if b, err := os.ReadFile(file); err == nil {
			if strings.TrimSpace(string(b)) != password {
				fmt.Fprintln(stderr, "grantline: database secret mismatch; restore the matching secret set")
				return 2
			}
		} else if !os.IsNotExist(err) {
			return 2
		} else if os.WriteFile(file, []byte(password+"\n"), 0444) != nil {
			return 2
		}
	}
	if _, e = create("encryption-key", 32); e != nil {
		return 2
	}
	if _, e = create("setup-token", 32); e != nil {
		return 2
	}
	path := filepath.Join(*dir, "database-url")
	if _, e = os.Stat(path); os.IsNotExist(e) {
		value := "postgres://grantline:" + password + "@" + *host + ":5432/grantline?sslmode=disable\n"
		if e = os.WriteFile(path, []byte(value), 0600); e != nil {
			return 2
		}
	} else if e != nil {
		return 2
	}
	fmt.Fprintln(stdout, "Initialization complete. Existing secrets were preserved. Read setup-token locally to create the first owner.")
	return 0
}
