// Package accountmanager manages NATS identities. KV is the encrypted management
// store; the server's account resolver remains the authority for account JWTs.
package accountmanager

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

const Bucket = "NATS_DESKTOP_IDENTITIES"
const workspaceKey = "workspace"

// Workspace is never stored in plaintext. All seeds, claims and credentials
// reside in one encrypted, revision-checked KV record to avoid partial updates.
type Workspace struct {
	Version       int                 `json:"version"`
	OperatorJWT   string              `json:"operator_jwt"`
	OperatorSeed  string              `json:"operator_seed"`
	SystemAccount string              `json:"system_account"`
	Accounts      map[string]*Account `json:"accounts"`
}

type Account struct {
	Name  string           `json:"name"`
	Seed  string           `json:"seed"`
	JWT   string           `json:"jwt"`
	Users map[string]*User `json:"users"`
}

type User struct {
	Name string `json:"name"`
	Seed string `json:"seed"`
	JWT  string `json:"jwt"`
}

// Envelope has no identifying metadata except its format version and the KDF
// parameters. The associated data binds ciphertext to this storage purpose.
type Envelope struct {
	Version int    `json:"version"`
	Salt    []byte `json:"salt"`
	Nonce   []byte `json:"nonce"`
	Data    []byte `json:"data"`
}

var associatedData = []byte("nats-desktop/identities/workspace/v1")

func Encrypt(w *Workspace, passphrase string) ([]byte, error) {
	if len(passphrase) < 12 {
		return nil, errors.New("master passphrase must contain at least 12 characters")
	}
	plaintext, err := json.Marshal(w)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	var env Envelope
	env.Version = 1
	env.Salt = make([]byte, 16)
	env.Nonce = make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, env.Salt); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, env.Nonce); err != nil {
		return nil, err
	}
	key, err := pbkdf2.Key(sha256.New, passphrase, env.Salt, 600_000, 32)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	env.Data = gcm.Seal(nil, env.Nonce, plaintext, associatedData)
	return json.Marshal(env)
}

func Decrypt(data []byte, passphrase string) (*Workspace, error) {
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("invalid encrypted workspace: %w", err)
	}
	if env.Version != 1 || len(env.Salt) != 16 || len(env.Nonce) != 12 || len(env.Data) < 16 {
		return nil, errors.New("unsupported or malformed encrypted workspace")
	}
	key, err := pbkdf2.Key(sha256.New, passphrase, env.Salt, 600_000, 32)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, env.Nonce, env.Data, associatedData)
	if err != nil {
		return nil, errors.New("incorrect passphrase or damaged workspace")
	}
	defer clear(plaintext)
	var w Workspace
	if err := json.Unmarshal(plaintext, &w); err != nil {
		return nil, err
	}
	if w.Version != 1 || w.Accounts == nil {
		return nil, errors.New("unsupported workspace version")
	}
	return &w, nil
}

func NewWorkspace(operatorJWT, operatorSeed, systemAccount string) (*Workspace, error) {
	claims, err := jwt.DecodeOperatorClaims(strings.TrimSpace(operatorJWT))
	if err != nil {
		return nil, fmt.Errorf("invalid operator JWT: %w", err)
	}
	seed := strings.TrimSpace(operatorSeed)
	pair, err := nkeys.FromSeed([]byte(seed))
	if err != nil {
		return nil, fmt.Errorf("invalid signing seed: %w", err)
	}
	defer pair.Wipe()
	pub, err := pair.PublicKey()
	if err != nil {
		return nil, err
	}
	if pub != claims.Subject && !claims.SigningKeys.Contains(pub) {
		return nil, errors.New("seed is not trusted by the operator JWT")
	}
	if systemAccount == "" {
		systemAccount = claims.SystemAccount
	}
	if systemAccount != claims.SystemAccount || !nkeys.IsValidPublicAccountKey(systemAccount) {
		return nil, errors.New("system account does not match the operator JWT")
	}
	return &Workspace{Version: 1, OperatorJWT: operatorJWT, OperatorSeed: seed, SystemAccount: systemAccount, Accounts: make(map[string]*Account)}, nil
}
