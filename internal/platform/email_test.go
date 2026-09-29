package platform

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"net"
	"net/http/httptest"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testSMTP(t *testing.T, reject bool) (string, string, <-chan string) {
	t.Helper()
	certificate := httptest.NewTLSServer(nil)
	config := certificate.TLS.Clone()
	certificate.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	ca := filepath.Join(t.TempDir(), "smtp-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: config.Certificates[0].Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	messages := make(chan string, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		connection.SetDeadline(time.Now().Add(5 * time.Second))
		protocol := textproto.NewConn(connection)
		if protocol.PrintfLine("220 fixture ESMTP") != nil {
			return
		}
		for {
			line, err := protocol.ReadLine()
			if err != nil {
				return
			}
			switch {
			case strings.HasPrefix(line, "EHLO "):
				protocol.PrintfLine("250-fixture\r\n250 AUTH PLAIN")
			case strings.HasPrefix(line, "AUTH PLAIN "):
				decoded, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, "AUTH PLAIN "))
				if reject || string(decoded) != "\x00observer\x00fixture-mail-password" {
					protocol.PrintfLine("535 Authentication rejected")
				} else {
					protocol.PrintfLine("235 Authenticated")
				}
			case strings.HasPrefix(line, "MAIL FROM:") || strings.HasPrefix(line, "RCPT TO:"):
				protocol.PrintfLine("250 Accepted")
			case line == "DATA":
				protocol.PrintfLine("354 Send message")
				body, err := protocol.ReadDotBytes()
				if err != nil {
					return
				}
				messages <- string(body)
				protocol.PrintfLine("250 Queued")
			case line == "QUIT":
				protocol.PrintfLine("221 Goodbye")
				return
			default:
				protocol.PrintfLine("500 Unsupported")
			}
		}
	}()
	return listener.Addr().String(), ca, messages
}

func TestAccountEmailVerifiedTLSAndAuthentication(t *testing.T) {
	for _, mode := range []string{"success", "untrusted", "authentication"} {
		t.Run(mode, func(t *testing.T) {
			address, ca, messages := testSMTP(t, mode == "authentication")
			cfg := Config{PublicURL: "http://127.0.0.1:8080", SMTPAddress: address, SMTPFrom: "grantline@example.test", SMTPUsername: "observer", SMTPPassword: "fixture-mail-password", CustomCA: ca}
			if mode == "untrusted" {
				cfg.CustomCA = ""
			}
			s := &Server{cfg: cfg}
			err := s.sendAccountEmail(context.Background(), "analyst@example.test", "recovery", "https://grantline.example.test/#accept/synthetic-ticket")
			if mode != "success" {
				if err == nil {
					t.Fatal("untrusted or unauthenticated mail delivery accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			select {
			case message := <-messages:
				for _, expected := range []string{"To: analyst@example.test", "Subject: Reset your Grantline password", "https://grantline.example.test/#accept/synthetic-ticket"} {
					if !strings.Contains(message, expected) {
						t.Fatalf("missing mail field %q", expected)
					}
				}
			case <-time.After(time.Second):
				t.Fatal("SMTP did not receive message")
			}
		})
	}
}

func TestDatabaseEmailDeliveryBoundedRetries(t *testing.T) {
	db := testDatabase(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	s, err := New(db, Config{PublicURL: "http://127.0.0.1:8080", SetupToken: randomID(), EncryptionKey: randomBytes(32), SMTPAddress: address, SMTPFrom: "grantline@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err = s.queueAccountEmail(context.Background(), tx, "analyst@example.test", "invite", "https://grantline.example.test/#accept/synthetic-ticket"); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt <= 3; attempt++ {
		s.deliverEmail(context.Background())
		var state string
		var attempts int
		if err = db.QueryRow("SELECT state,attempts FROM email_jobs").Scan(&state, &attempts); err != nil {
			t.Fatal(err)
		}
		want := "queued"
		if attempt == 3 {
			want = "failed"
		}
		if state != want || attempts != attempt {
			t.Fatalf("attempt %d: %s / %d", attempt, state, attempts)
		}
		if _, err = db.Exec("UPDATE email_jobs SET next_attempt=now()"); err != nil {
			t.Fatal(err)
		}
	}
	s.deliverEmail(context.Background())
	var attempts int
	if err = db.QueryRow("SELECT attempts FROM email_jobs").Scan(&attempts); err != nil || attempts != 3 {
		t.Fatal("failed email was retried without a bound")
	}
}
