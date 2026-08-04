package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestGenerateProof(t *testing.T) {
	verifier := []byte("test-verifier")
	nonce := []byte("test-nonce")
	proof := GenerateProof(verifier, nonce)
	// Compute expected HMAC-SHA256
	mac := hmac.New(sha256.New, verifier)
	mac.Write(nonce)
	expected := mac.Sum(nil)
	if !bytes.Equal(proof, expected) {
		t.Fatalf("expected %s, got %s", hex.EncodeToString(expected), hex.EncodeToString(proof))
	}
}

func TestConstantTimeCompareEqual(t *testing.T) {
	a := []byte("hello")
	b := []byte("hello")
	if !ConstantTimeCompare(a, b) {
		t.Fatal("expected true for equal inputs")
	}
}

func TestConstantTimeCompareNotEqual(t *testing.T) {
	a := []byte("hello")
	b := []byte("world")
	if ConstantTimeCompare(a, b) {
		t.Fatal("expected false for unequal inputs")
	}
}