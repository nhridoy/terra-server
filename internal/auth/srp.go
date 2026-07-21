package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
)

// SRP6a implementation matching Termius
// Uses 2048-bit prime and SHA-256

// Safe prime for SRP (RFC 5054 2048-bit)
var srpPrimeHex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"

var srpPrime *big.Int
var srpGenerator *big.Int

func init() {
	srpPrime = new(big.Int)
	srpPrime.SetString(srpPrimeHex, 16)
	srpGenerator = big.NewInt(2)
}

type SRPServer struct {
	UserID    string
	Email     string
	Salt      []byte
	Verifier  *big.Int
	B         *big.Int // server public value
	b         *big.Int // server private value
}

type SRPClientHello struct {
	Email string `json:"email"`
	A     string `json:"a"` // client public value
}

type SRPServerHello struct {
	Salt     string `json:"salt"`
	B        string `json:"b"`
	SRPProof string `json:"srpProof"`
}

type SRPClientProof struct {
	M1 string `json:"m1"`
}

type SRPServerProof struct {
	M2     string `json:"m2"`
	Token  string `json:"token"`
	UserID string `json:"userId"`
}

// CalculateVerifier computes the SRP verifier from password
func CalculateVerifier(password string, salt []byte) *big.Int {
	x := calculateX(password, salt)
	verifier := new(big.Int).Exp(srpGenerator, x, srpPrime)
	return verifier
}

// GenerateVerifier creates a new verifier for registration
func GenerateVerifier(email, password string, salt []byte) (*big.Int, error) {
	verifier := CalculateVerifier(password, salt)
	return verifier, nil
}

// VerifyPassword verifies a password against stored salt and verifier
func VerifyPassword(email, password string, salt, verifierBytes []byte) bool {
	verifier := CalculateVerifier(password, salt)
	expectedVerifier := new(big.Int).SetBytes(verifierBytes)
	return verifier.Cmp(expectedVerifier) == 0
}

func calculateX(password string, salt []byte) *big.Int {
	h := sha256.New()
	h.Write([]byte(password))
	passwordHash := h.Sum(nil)

	h.Reset()
	h.Write(salt)
	h.Write(passwordHash)
	x := new(big.Int).SetBytes(h.Sum(nil))
	return x
}

// CreateServerChallenge generates server public value B
func CreateServerChallenge(verifier *big.Int) (*SRPServer, error) {
	bBytes := make([]byte, 128)
	if _, err := rand.Read(bBytes); err != nil {
		return nil, err
	}
	b := new(big.Int).SetBytes(bBytes)

	k := calculateK()

	kv := new(big.Int).Mul(k, verifier)
	kv.Mod(kv, srpPrime)

	gb := new(big.Int).Exp(srpGenerator, b, srpPrime)

	B := new(big.Int).Add(kv, gb)
	B.Mod(B, srpPrime)

	return &SRPServer{
		B: B,
		b: b,
	}, nil
}

func calculateK() *big.Int {
	h := sha256.New()
	h.Write(srpPrime.Bytes())
	h.Write(srpGenerator.Bytes())
	k := new(big.Int).SetBytes(h.Sum(nil))
	return k
}

// CalculateSessionKey computes the shared session key
func (s *SRPServer) CalculateSessionKey(A *big.Int) []byte {
	h := sha256.New()
	h.Write(A.Bytes())
	h.Write(s.B.Bytes())
	u := new(big.Int).SetBytes(h.Sum(nil))

	vu := new(big.Int).Exp(s.Verifier, u, srpPrime)
	avu := new(big.Int).Mul(A, vu)
	S := new(big.Int).Exp(avu, s.b, srpPrime)

	h.Reset()
	h.Write(S.Bytes())
	K := h.Sum(nil)

	return K
}

// CalculateServerProof computes M2 for server proof
func (s *SRPServer) CalculateServerProof(A *big.Int, M1 []byte, K []byte) []byte {
	h := sha256.New()
	h.Write(A.Bytes())
	h.Write(M1)
	h.Write(K)
	return h.Sum(nil)
}

// ValidateClientProof validates M1 from client
func ValidateClientProof(email string, password string, salt []byte, A *big.Int, M1 []byte) bool {
	h := sha256.New()
	h.Write(A.Bytes())

	verifier := CalculateVerifier(password, salt)
	h.Write(verifier.Bytes())

	x := calculateX(password, salt)
	h.Write(x.Bytes())

	expectedM1 := h.Sum(nil)

	if len(M1) != len(expectedM1) {
		return false
	}
	for i := range M1 {
		if M1[i] != expectedM1[i] {
			return false
		}
	}
	return true
}

// HexToBytes converts a hex string to bytes
func HexToBytes(hexStr string) ([]byte, error) {
	if len(hexStr)%2 != 0 {
		hexStr = "0" + hexStr
	}
	return hex.DecodeString(hexStr)
}

// BytesToHex converts bytes to a hex string
func BytesToHex(bytes []byte) string {
	return hex.EncodeToString(bytes)
}

// BigIntToHex converts a big.Int to a hex string
func BigIntToHex(n *big.Int) string {
	h := n.Text(16)
	if len(h)%2 != 0 {
		h = "0" + h
	}
	return h
}

// HexToBigInt converts a hex string to a big.Int
func HexToBigInt(hexStr string) *big.Int {
	n := new(big.Int)
	n.SetString(hexStr, 16)
	return n
}
