package accountmanager

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func TestBootstrapClaimsAndEncryption(t *testing.T) {
	b, err := NewBootstrap("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.Config, "resolver_preload") || strings.Contains(b.Config, b.Workspace.OperatorSeed) {
		t.Fatal("bootstrap config missing resolver or leaked signing seed")
	}
	w, err := Decrypt(b.Recovery, "correct horse battery staple")
	if err != nil || w.SystemAccount != b.Workspace.SystemAccount {
		t.Fatalf("recovery roundtrip failed: %v", err)
	}
	if _, err := Decrypt(b.Recovery, "incorrect passphrase"); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	corrupt := bytes.Clone(b.Recovery)
	corrupt[len(corrupt)-12] ^= 1
	if _, err := Decrypt(corrupt, "correct horse battery staple"); err == nil {
		t.Fatal("tampered workspace accepted")
	}
	op, err := jwt.DecodeOperatorClaims(b.OperatorJWT)
	if err != nil || op.SystemAccount != w.SystemAccount {
		t.Fatalf("invalid bootstrap operator: %v", err)
	}
	dir := filepath.Join(t.TempDir(), "deployment")
	if err := b.Write(dir); err != nil {
		t.Fatal(err)
	}
	if err := b.Write(dir); err == nil {
		t.Fatal("overwrote an existing deployment")
	}
	info, err := os.Stat(filepath.Join(dir, "recovery.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("recovery file permissions: %v", err)
	}
	// Use absolute paths to ensure config parsing does not depend on cwd.
	config, err := os.ReadFile(filepath.Join(dir, "nats-server.conf"))
	if err != nil {
		t.Fatal(err)
	}
	s := strings.ReplaceAll(string(config), "./operator.jwt", filepath.Join(dir, "operator.jwt"))
	s = strings.ReplaceAll(s, "./resolver", filepath.Join(dir, "resolver"))
	s = strings.ReplaceAll(s, "./jetstream", filepath.Join(dir, "jetstream"))
	path := filepath.Join(dir, "test.conf")
	if err := os.WriteFile(path, []byte(s), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := server.ProcessConfigFile(path); err != nil {
		t.Fatalf("generated server config invalid: %v", err)
	}
}

func TestClaims(t *testing.T) {
	b, err := NewBootstrap("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	w := b.Workspace
	pub, token, err := w.CreateAccount("Orders")
	if err != nil {
		t.Fatal(err)
	}
	if c, err := jwt.DecodeAccountClaims(token); err != nil || c.Subject != pub {
		t.Fatalf("invalid account JWT: %v", err)
	}
	if _, _, err := w.CreateAccount("orders"); err == nil {
		t.Fatal("duplicate account name accepted")
	}
	user, creds, err := w.CreateUser(pub, "reader")
	if err != nil || user == "" || !bytes.Contains(creds, []byte("BEGIN NATS USER JWT")) {
		t.Fatalf("invalid user credentials: %v", err)
	}
	if _, err := w.AddExport(pub, "orders.>", jwt.Stream); err != nil {
		t.Fatal(err)
	}
	other, _, err := w.CreateAccount("Shipping")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.AddImport(other, pub, "orders.>", "received.>", jwt.Stream); err != nil {
		t.Fatal(err)
	}
	c, _ := jwt.DecodeAccountClaims(w.Accounts[other].JWT)
	if len(c.Imports) != 1 || c.Imports[0].Account != pub {
		t.Fatal("missing import")
	}
	if _, err := w.AddExportWithAccess(pub, "private.>", jwt.Stream, true); err != nil {
		t.Fatal(err)
	}
	if _, err := w.AddImport(other, pub, "private.>", "internal.>", jwt.Stream); err != nil {
		t.Fatal(err)
	}
	c, _ = jwt.DecodeAccountClaims(w.Accounts[other].JWT)
	if len(c.Imports) != 2 || c.Imports[1].Token == "" {
		t.Fatal("private import missing activation")
	}
}

func TestResolverAndKVIntegration(t *testing.T) {
	b, err := NewBootstrap("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "deployment")
	if err := b.Write(dir); err != nil {
		t.Fatal(err)
	}
	config := strings.ReplaceAll(b.Config, "./operator.jwt", filepath.Join(dir, "operator.jwt"))
	config = strings.ReplaceAll(config, "./resolver", filepath.Join(dir, "resolver"))
	config = strings.ReplaceAll(config, "./jetstream", filepath.Join(dir, "jetstream"))
	path := filepath.Join(dir, "server.conf")
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	opts, err := server.ProcessConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	opts.Port = -1
	opts.NoLog = true
	opts.NoSigs = true
	s, err := server.NewServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	go s.Start()
	defer s.Shutdown()
	if !s.ReadyForConnections(10 * time.Second) {
		t.Fatal("test server not ready")
	}
	system, err := nats.Connect(s.ClientURL(), nats.UserCredentials(filepath.Join(dir, "system.creds")))
	if err != nil {
		t.Fatal(err)
	}
	defer system.Close()
	management, err := nats.Connect(s.ClientURL(), nats.UserCredentials(filepath.Join(dir, "management.creds")))
	if err != nil {
		t.Fatal(err)
	}
	defer management.Close()
	js, err := jetstream.New(management)
	if err != nil {
		t.Fatal(err)
	}
	m := Manager{System: system, JS: js}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := m.Create(ctx, b.Workspace, "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	w, rev, err := m.Load(ctx, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	pub, token, err := w.CreateAccount("Orders")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Apply(ctx, w, "correct horse battery staple", rev, token); err != nil {
		t.Fatal(err)
	}
	_, creds, err := w.CreateUser(pub, "reader")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Save(ctx, w, "correct horse battery staple", rev); err == nil {
		t.Fatal("stale revision accepted")
	}
	if _, err := m.Apply(ctx, w, "correct horse battery staple", rev, "invalid-jwt"); err == nil || !strings.Contains(err.Error(), "changed concurrently") {
		t.Fatalf("stale edit reached the resolver: %v", err)
	}
	credentialPath := filepath.Join(dir, "reader.creds")
	if err := os.WriteFile(credentialPath, creds, 0600); err != nil {
		t.Fatal(err)
	}
	conn, err := nats.Connect(s.ClientURL(), nats.UserCredentials(credentialPath))
	if err != nil {
		t.Fatalf("newly issued user could not connect: %v", err)
	}
	conn.Close()
	existingDir := filepath.Join(t.TempDir(), "existing")
	onboard, imported, credPath, err := OnboardExisting(ctx, system, b.OperatorJWT, b.Workspace.OperatorSeed, "correct horse battery staple", s.ClientURL(), existingDir)
	if err != nil {
		t.Fatalf("existing server onboarding: %v", err)
	}
	if len(imported.Accounts) != 1 {
		t.Fatal("expected a new management account")
	}
	onboard.Close()
	reopened, _, _, err := Connect(ctx, system, s.ClientURL(), credPath, "correct horse battery staple", "")
	if err != nil {
		t.Fatalf("cannot reopen existing server workspace: %v", err)
	}
	reopened.Close()
}
