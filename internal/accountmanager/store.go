package accountmanager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Manager uses separate connections: the system account updates the native
// resolver, while a JetStream-enabled management account owns the KV bucket.
type Manager struct {
	System     *nats.Conn
	JS         jetstream.JetStream
	KV         jetstream.KeyValue
	connection *nats.Conn
}

// Close releases the management connection, not the application's system connection.
func (m *Manager) Close() {
	if m != nil && m.connection != nil {
		m.connection.Close()
	}
}

func (m *Manager) Open(ctx context.Context) error {
	if m.JS == nil {
		return errors.New("management JetStream connection is required")
	}
	kv, err := m.JS.KeyValue(ctx, Bucket)
	if err != nil {
		return fmt.Errorf("open management bucket: %w", err)
	}
	m.KV = kv
	return nil
}

func (m *Manager) Create(ctx context.Context, w *Workspace, passphrase string) error {
	if m.JS == nil {
		return errors.New("management JetStream connection is required")
	}
	kv, err := m.JS.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: Bucket, History: 5, Storage: jetstream.FileStorage})
	if err != nil {
		return fmt.Errorf("create management bucket: %w", err)
	}
	m.KV = kv
	data, err := Encrypt(w, passphrase)
	if err != nil {
		return err
	}
	if _, err := kv.Create(ctx, workspaceKey, data); err != nil {
		return fmt.Errorf("initialize workspace (bucket may already contain data): %w", err)
	}
	return nil
}

func (m *Manager) Load(ctx context.Context, passphrase string) (*Workspace, uint64, error) {
	if m.KV == nil {
		return nil, 0, errors.New("management bucket is not open")
	}
	entry, err := m.KV.Get(ctx, workspaceKey)
	if err != nil {
		return nil, 0, err
	}
	w, err := Decrypt(entry.Value(), passphrase)
	return w, entry.Revision(), err
}

func (m *Manager) Save(ctx context.Context, w *Workspace, passphrase string, revision uint64) (uint64, error) {
	if m.KV == nil || revision == 0 {
		return 0, errors.New("load the management workspace before editing")
	}
	data, err := Encrypt(w, passphrase)
	if err != nil {
		return 0, err
	}
	rev, err := m.KV.Update(ctx, workspaceKey, data, revision)
	if err != nil {
		return 0, fmt.Errorf("workspace changed concurrently; reload and verify resolver state: %w", err)
	}
	return rev, nil
}

// PublishAccount checks the resolver's response; successful KV storage alone
// does not make an account usable. Requesting from the system account is
// required. A publish followed by a KV failure needs explicit reconciliation.
func (m *Manager) PublishAccount(ctx context.Context, token string) error {
	if m.System == nil || !m.System.IsConnected() {
		return errors.New("connected system-account credential is required")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	msg, err := m.System.RequestWithContext(ctx, "$SYS.REQ.CLAIMS.UPDATE", []byte(token))
	if err != nil {
		return fmt.Errorf("resolver update failed (check system credential and NATS-based resolver): %w", err)
	}
	var reply struct {
		Data *struct {
			Code int `json:"code"`
		} `json:"data"`
		Error *struct {
			Description string `json:"description"`
		} `json:"error"`
	}
	if err := json.Unmarshal(msg.Data, &reply); err != nil {
		return fmt.Errorf("invalid resolver response: %w", err)
	}
	if reply.Error != nil {
		return fmt.Errorf("resolver rejected account JWT: %s", reply.Error.Description)
	}
	if reply.Data == nil || reply.Data.Code != 200 {
		return errors.New("resolver did not confirm account JWT update")
	}
	return nil
}

// Apply publishes the account JWT before persisting the new encrypted state.
// The caller must reload on failure; NATS resolver and KV have no atomic
// cross-service transaction.
func (m *Manager) Apply(ctx context.Context, w *Workspace, passphrase string, revision uint64, token string) (uint64, error) {
	if m.KV == nil || revision == 0 {
		return 0, errors.New("load the management workspace before editing")
	}
	entry, err := m.KV.Get(ctx, workspaceKey)
	if err != nil {
		return 0, fmt.Errorf("check workspace revision: %w", err)
	}
	if entry.Revision() != revision {
		return 0, errors.New("workspace changed concurrently; lock and unlock to reload before editing")
	}
	if err := m.PublishAccount(ctx, token); err != nil {
		return 0, err
	}
	rev, err := m.Save(ctx, w, passphrase, revision)
	if err != nil {
		return 0, fmt.Errorf("resolver updated but encrypted workspace was not saved; reconcile before retrying: %w", err)
	}
	return rev, nil
}
