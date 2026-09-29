package platform

import (
	"bytes"
	"encoding/base32"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestEncryptedCredentialsAreBoundToConnection(t *testing.T) {
	key := randomBytes(32)
	clear := []byte("observer credential")
	encrypted, err := seal(key, "connection:a", clear)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted, clear) {
		t.Fatal("plaintext credential in ciphertext")
	}
	restored, err := unseal(key, "connection:a", encrypted)
	if err != nil || !bytes.Equal(restored, clear) {
		t.Fatal("roundtrip failed")
	}
	for _, test := range []struct {
		key   []byte
		label string
		value []byte
	}{{key, "connection:b", encrypted}, {randomBytes(32), "connection:a", encrypted}, {key, "connection:a", encrypted[:12]}} {
		if _, err := unseal(test.key, test.label, test.value); err == nil {
			t.Fatal("accepted mismatched credentials")
		}
	}
	encrypted[len(encrypted)-1] ^= 1
	if _, err := unseal(key, "connection:a", encrypted); err == nil {
		t.Fatal("accepted altered ciphertext")
	}
}
func TestPasswordStorage(t *testing.T) {
	pass := "a sufficiently long local passphrase"
	a, e := passwordHash(pass)
	if e != nil {
		t.Fatal(e)
	}
	b, e := passwordHash(pass)
	if e != nil {
		t.Fatal(e)
	}
	if a == b || !passwordMatches(a, pass) || passwordMatches(a, "wrong password") {
		t.Fatal("password verification or salt failure")
	}
	if _, e := passwordHash("short"); e == nil {
		t.Fatal("short password accepted")
	}
	if passwordMatches("argon2id$9999999$65536$2$x$y", pass) {
		t.Fatal("unbounded hash accepted")
	}
}
func TestTOTPRFC6238(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	for _, v := range []struct {
		at   int64
		want string
	}{{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"}, {1234567890, "005924"}, {2000000000, "279037"}, {20000000000, "353130"}} {
		if got := totpCode(secret, v.at/30); got != v.want {
			t.Fatalf("RFC code at %d: got %s", v.at, got)
		}
		if totpStep(secret, v.want, time.Unix(v.at, 0)) != v.at/30 {
			t.Fatal("valid code rejected")
		}
	}
	if totpStep(secret, "123", time.Now()) != 0 {
		t.Fatal("malformed code accepted")
	}
}
func TestForwardedAddressRequiresTrustedHops(t *testing.T) {
	s := &Server{cfg: Config{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}}}
	r := httptest.NewRequest("GET", "https://grantline.example", nil)
	r.RemoteAddr = "192.0.2.4:2000"
	r.Header.Set("X-Forwarded-For", "203.0.113.7")
	if s.clientAddress(r) != "192.0.2.4" {
		t.Fatal("trusted an untrusted forwarding header")
	}
	r.RemoteAddr = "10.20.0.2:2000"
	r.Header.Set("X-Forwarded-For", "203.0.113.7, 192.0.2.4, 10.20.0.3")
	if s.clientAddress(r) != "192.0.2.4" {
		t.Fatal("did not stop at first untrusted hop")
	}
}
