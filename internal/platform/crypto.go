// Package platform implements the persistent, single-organization server.
package platform

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"strings"
	"time"
)

func randomID() string { return base64.RawURLEncoding.EncodeToString(randomBytes(24)) }
func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("operating system randomness unavailable")
	}
	return b
}
func digest(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func seal(key []byte, label string, clear []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	a, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := randomBytes(a.NonceSize())
	return a.Seal(nonce, nonce, clear, []byte(label)), nil
}
func unseal(key []byte, label string, encrypted []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	a, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(encrypted) < a.NonceSize() {
		return nil, errors.New("encrypted value unavailable")
	}
	return a.Open(nil, encrypted[:a.NonceSize()], encrypted[a.NonceSize():], []byte(label))
}
func passwordHash(password string) (string, error) {
	if len(password) < 15 || len(password) > 256 {
		return "", errors.New("Use a password between 15 and 256 bytes")
	}
	salt := randomBytes(16)
	key := argon2.IDKey([]byte(password), salt, 3, 64*1024, 2, 32)
	return "argon2id$3$65536$2$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(key), nil
}
func passwordMatches(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "argon2id" || parts[1] != "3" || parts[2] != "65536" || parts[3] != "2" || len(password) > 256 {
		return false
	}
	salt, e1 := base64.RawStdEncoding.DecodeString(parts[4])
	want, e2 := base64.RawStdEncoding.DecodeString(parts[5])
	if e1 != nil || e2 != nil || len(salt) != 16 || len(want) != 32 {
		return false
	}
	actual := argon2.IDKey([]byte(password), salt, 3, 64*1024, 2, 32)
	return subtle.ConstantTimeCompare(actual, want) == 1
}
func newTOTP() string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(randomBytes(20))
}
func totpCode(secret string, step int64) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return ""
	}
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(step))
	h := hmac.New(sha1.New, key)
	h.Write(b)
	sum := h.Sum(nil)
	offset := int(sum[len(sum)-1] & 15)
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[offset:offset+4])&0x7fffffff)%1000000)
}
func totpStep(secret, code string, now time.Time) int64 {
	if len(code) != 6 {
		return 0
	}
	step := now.Unix() / 30
	for _, i := range []int64{0, -1, 1} {
		if subtle.ConstantTimeCompare([]byte(totpCode(secret, step+i)), []byte(code)) == 1 {
			return step + i
		}
	}
	return 0
}
