package accountmanager

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// OnboardExisting provisions a separate JetStream-enabled management account
// through the connected system account, then creates the encrypted KV store.
// The caller supplies the operator JWT as well as an operator or trusted
// signing seed; knowing a seed alone cannot establish server trust.
func OnboardExisting(ctx context.Context, system *nats.Conn, operatorJWT, signingSeed, passphrase, url, exportDir string) (*Manager, *Workspace, string, error) {
	w, err := NewWorkspace(operatorJWT, signingSeed, "")
	if err != nil {
		return nil, nil, "", err
	}
	pub, token, err := w.CreateAccount("NATS Desktop Management")
	if err != nil {
		return nil, nil, "", err
	}
	_, creds, err := w.CreateUser(pub, "Desktop management administrator")
	if err != nil {
		return nil, nil, "", err
	}
	recovery, err := Encrypt(w, passphrase)
	if err != nil {
		return nil, nil, "", err
	}
	if err := os.Mkdir(exportDir, 0700); err != nil {
		return nil, nil, "", fmt.Errorf("create empty recovery directory: %w", err)
	}
	credsPath := filepath.Join(exportDir, "management.creds")
	for name, data := range map[string][]byte{"management.creds": creds, "recovery.json": recovery} {
		f, err := os.OpenFile(filepath.Join(exportDir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, nil, "", err
		}
		_, writeErr := f.Write(data)
		closeErr := f.Close()
		if writeErr != nil {
			return nil, nil, "", writeErr
		}
		if closeErr != nil {
			return nil, nil, "", closeErr
		}
	}
	m := &Manager{System: system}
	if err := m.PublishAccount(ctx, token); err != nil {
		return nil, nil, "", err
	}
	management, err := nats.Connect(url, nats.UserCredentials(credsPath))
	if err != nil {
		return nil, nil, "", fmt.Errorf("management account published but cannot connect: %w", err)
	}
	js, err := jetstream.New(management)
	if err != nil {
		management.Close()
		return nil, nil, "", err
	}
	m.JS = js
	m.connection = management
	if err := m.Create(ctx, w, passphrase); err != nil {
		management.Close()
		return nil, nil, "", fmt.Errorf("management account published but KV setup failed; keep the recovery export: %w", err)
	}
	return m, w, credsPath, nil
}

// Connect opens an existing workspace. If the KV bucket does not exist yet,
// the required recovery export can initialize it after deploying a new server.
func Connect(ctx context.Context, system *nats.Conn, url, managementCreds, passphrase, recoveryPath string) (*Manager, *Workspace, uint64, error) {
	management, err := nats.Connect(url, nats.UserCredentials(managementCreds))
	if err != nil {
		return nil, nil, 0, err
	}
	js, err := jetstream.New(management)
	if err != nil {
		management.Close()
		return nil, nil, 0, err
	}
	m := &Manager{System: system, JS: js, connection: management}
	if err := m.Open(ctx); err != nil {
		if recoveryPath == "" {
			management.Close()
			return nil, nil, 0, fmt.Errorf("KV bucket unavailable; provide the recovery export to initialize it: %w", err)
		}
		data, readErr := os.ReadFile(recoveryPath)
		if readErr != nil {
			management.Close()
			return nil, nil, 0, readErr
		}
		w, decodeErr := Decrypt(data, passphrase)
		if decodeErr != nil {
			management.Close()
			return nil, nil, 0, decodeErr
		}
		if err := m.Create(ctx, w, passphrase); err != nil {
			management.Close()
			return nil, nil, 0, err
		}
	}
	w, rev, err := m.Load(ctx, passphrase)
	if err != nil {
		management.Close()
		return nil, nil, 0, err
	}
	return m, w, rev, nil
}
