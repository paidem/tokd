package server

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

type sealer struct{ aead cipher.AEAD }

// loadKey reads a base64 32-byte key, creating it (0600) if the file does not exist.
func loadKey(path string) (*sealer, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		k := make([]byte, 32)
		rand.Read(k)
		raw = []byte(base64.StdEncoding.EncodeToString(k) + "\n")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			return nil, fmt.Errorf("create key: %w", err)
		}
	} else if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("key file %s: want base64 of 32 bytes", path)
	}
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	return &sealer{aead}, nil
}

// seal binds the ciphertext to the token name, so rows can't be swapped.
func (s *sealer) seal(name, plain string) []byte {
	nonce := make([]byte, s.aead.NonceSize())
	rand.Read(nonce)
	return s.aead.Seal(nonce, nonce, []byte(plain), []byte(name))
}

func (s *sealer) open(name string, blob []byte) (string, error) {
	n := s.aead.NonceSize()
	if len(blob) < n {
		return "", errors.New("ciphertext too short")
	}
	p, err := s.aead.Open(nil, blob[:n], blob[n:], []byte(name))
	return string(p), err
}

// mask shows a few characters at each end; values shorter than 10 are fully hidden.
func mask(v string) string {
	r := []rune(v)
	if len(r) < 10 {
		return strings.Repeat("•", 8)
	}
	k := min(4, len(r)/5)
	return string(r[:k]) + strings.Repeat("•", 8) + string(r[len(r)-k:])
}

func randToken(nbytes int) string {
	b := make([]byte, nbytes)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

// userCode is what you type/compare in the browser during `tok login`: XXXX-XXXX, no ambiguous chars.
func userCode() string {
	const alphabet = "BCDFGHJKLMNPQRSTVWXZ23456789"
	b := make([]byte, 8)
	rand.Read(b)
	out := make([]byte, 0, 9)
	for i, c := range b {
		if i == 4 {
			out = append(out, '-')
		}
		out = append(out, alphabet[int(c)%len(alphabet)])
	}
	return string(out)
}
