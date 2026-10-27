package accountmanager

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// Bootstrap contains deployable public configuration, credentials needed for
// initial access, and an encrypted recovery bundle. It is not a running server.
type Bootstrap struct {
	Config          string
	OperatorJWT     string
	SystemJWT       string
	ManagementJWT   string
	SystemCreds     []byte
	ManagementCreds []byte
	Recovery        []byte
	Workspace       *Workspace
}

func NewBootstrap(passphrase string) (*Bootstrap, error) {
	opPair, opPub, opSeed, err := newPair(nkeys.PrefixByteOperator)
	if err != nil {
		return nil, err
	}
	defer opPair.Wipe()
	sysPair, sysPub, sysSeed, err := newPair(nkeys.PrefixByteAccount)
	if err != nil {
		return nil, err
	}
	defer sysPair.Wipe()
	mgmtPair, mgmtPub, mgmtSeed, err := newPair(nkeys.PrefixByteAccount)
	if err != nil {
		return nil, err
	}
	defer mgmtPair.Wipe()
	opClaim := jwt.NewOperatorClaims(opPub)
	opClaim.Name = "NATS Desktop"
	opClaim.SystemAccount = sysPub
	opJWT, err := opClaim.Encode(opPair)
	if err != nil {
		return nil, err
	}
	w, err := NewWorkspace(opJWT, opSeed, sysPub)
	if err != nil {
		return nil, fmt.Errorf("bootstrap workspace: %w", err)
	}
	sysClaim := jwt.NewAccountClaims(sysPub)
	sysClaim.Name = "SYS"
	sysJWT, err := sysClaim.Encode(opPair)
	if err != nil {
		return nil, err
	}
	mgmtClaim := jwt.NewAccountClaims(mgmtPub)
	mgmtClaim.Name = "NATS Desktop Management"
	mgmtClaim.Limits.JetStreamLimits = jwt.JetStreamLimits{MemoryStorage: -1, DiskStorage: -1, Streams: -1, Consumer: -1}
	mgmtJWT, err := mgmtClaim.Encode(opPair)
	if err != nil {
		return nil, err
	}
	w.Accounts[sysPub] = &Account{Name: "SYS", Seed: sysSeed, JWT: sysJWT, Users: make(map[string]*User)}
	w.Accounts[mgmtPub] = &Account{Name: "NATS Desktop Management", Seed: mgmtSeed, JWT: mgmtJWT, Users: make(map[string]*User)}
	_, sysCreds, err := w.CreateUser(sysPub, "Desktop system administrator")
	if err != nil {
		return nil, err
	}
	_, mgmtCreds, err := w.CreateUser(mgmtPub, "Desktop management administrator")
	if err != nil {
		return nil, err
	}
	recovery, err := Encrypt(w, passphrase)
	if err != nil {
		return nil, err
	}
	// JWTs in resolver_preload are public, signed claims. The operator JWT is
	// supplied via its own file. Seeds and credentials never appear in config.
	// Loopback only by default. Operators must configure TLS before exposing
	// credential-bearing client traffic to an external network.
	config := fmt.Sprintf("host: 127.0.0.1\nport: 4222\njetstream { store_dir: ./jetstream }\noperator: ./operator.jwt\nresolver: { type: full, dir: ./resolver }\nresolver_preload {\n  %s: %q\n  %s: %q\n}\n", sysPub, sysJWT, mgmtPub, mgmtJWT)
	return &Bootstrap{Config: config, OperatorJWT: opJWT, SystemJWT: sysJWT, ManagementJWT: mgmtJWT, SystemCreds: sysCreds, ManagementCreds: mgmtCreds, Recovery: recovery, Workspace: w}, nil
}

// Write exports everything needed to deploy and recover a new server. Files
// are exclusive so a previous workspace is never silently overwritten.
func (b *Bootstrap) Write(dir string) (err error) {
	if strings.TrimSpace(dir) == "" {
		return errors.New("choose an empty export directory")
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return fmt.Errorf("create export directory: %w", err)
	}
	var created []string
	defer func() {
		if err != nil {
			for _, path := range created {
				_ = os.Remove(path)
			}
			_ = os.Remove(dir)
		}
	}()
	files := map[string][]byte{
		"nats-server.conf": []byte(b.Config),
		"operator.jwt":     []byte(b.OperatorJWT),
		"system.jwt":       []byte(b.SystemJWT),
		"management.jwt":   []byte(b.ManagementJWT),
		"system.creds":     b.SystemCreds,
		"management.creds": b.ManagementCreds,
		"recovery.json":    b.Recovery,
	}
	for name, data := range files {
		path := filepath.Join(dir, name)
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return fmt.Errorf("export %s: %w", name, err)
		}
		created = append(created, path)
		_, writeErr := f.Write(data)
		closeErr := f.Close()
		if writeErr != nil {
			return fmt.Errorf("export %s: %w", name, writeErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close %s: %w", name, closeErr)
		}
	}
	return nil
}
