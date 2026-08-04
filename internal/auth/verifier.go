package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
)

func GenerateProof(verifier []byte, nonce []byte) []byte {
	mac := hmac.New(sha256.New, verifier)
	mac.Write(nonce)
	return mac.Sum(nil)
}

func ConstantTimeCompare(a []byte, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}