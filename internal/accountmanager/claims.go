package accountmanager

import (
	"errors"
	"fmt"
	"strings"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

func newPair(prefix nkeys.PrefixByte) (nkeys.KeyPair, string, string, error) {
	pair, err := nkeys.CreatePair(prefix)
	if err != nil {
		return nil, "", "", err
	}
	pub, err := pair.PublicKey()
	if err != nil {
		pair.Wipe()
		return nil, "", "", err
	}
	seed, err := pair.Seed()
	if err != nil {
		pair.Wipe()
		return nil, "", "", err
	}
	return pair, pub, string(seed), nil
}

func signer(seed string) (nkeys.KeyPair, error) {
	return nkeys.FromSeed([]byte(seed))
}

func validate(claims jwt.Claims) error {
	vr := jwt.CreateValidationResults()
	claims.Validate(vr)
	if vr.IsBlocking(true) {
		return errors.Join(vr.Errors()...)
	}
	return nil
}

// CreateAccount returns the signed JWT; publish it to the resolver before
// committing the workspace. A failed publish must not persist the new record.
func (w *Workspace) CreateAccount(name string) (string, string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", "", errors.New("account name is required")
	}
	for _, a := range w.Accounts {
		if strings.EqualFold(a.Name, name) {
			return "", "", errors.New("account name already exists")
		}
	}
	operator, err := signer(w.OperatorSeed)
	if err != nil {
		return "", "", err
	}
	defer operator.Wipe()
	pair, pub, seed, err := newPair(nkeys.PrefixByteAccount)
	if err != nil {
		return "", "", err
	}
	defer pair.Wipe()
	claim := jwt.NewAccountClaims(pub)
	claim.Name = name
	// A managed account must be able to create its own JetStream resources.
	claim.Limits.JetStreamLimits.MemoryStorage = -1
	claim.Limits.JetStreamLimits.DiskStorage = -1
	claim.Limits.JetStreamLimits.Streams = -1
	claim.Limits.JetStreamLimits.Consumer = -1
	if err := validate(claim); err != nil {
		return "", "", err
	}
	token, err := claim.Encode(operator)
	if err != nil {
		return "", "", err
	}
	w.Accounts[pub] = &Account{Name: name, Seed: seed, JWT: token, Users: make(map[string]*User)}
	return pub, token, nil
}

func (w *Workspace) CreateUser(accountPub, name string) (string, []byte, error) {
	a, ok := w.Accounts[accountPub]
	if !ok {
		return "", nil, errors.New("account is not managed by this workspace")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return "", nil, errors.New("user name is required")
	}
	for _, u := range a.Users {
		if strings.EqualFold(u.Name, name) {
			return "", nil, errors.New("user name already exists")
		}
	}
	account, err := signer(a.Seed)
	if err != nil {
		return "", nil, err
	}
	defer account.Wipe()
	pair, pub, seed, err := newPair(nkeys.PrefixByteUser)
	if err != nil {
		return "", nil, err
	}
	defer pair.Wipe()
	claim := jwt.NewUserClaims(pub)
	claim.Name = name
	if err := validate(claim); err != nil {
		return "", nil, err
	}
	token, err := claim.Encode(account)
	if err != nil {
		return "", nil, err
	}
	creds, err := jwt.FormatUserConfig(token, []byte(seed))
	if err != nil {
		return "", nil, err
	}
	if a.Users == nil {
		a.Users = make(map[string]*User)
	}
	a.Users[pub] = &User{Name: name, Seed: seed, JWT: token}
	return pub, creds, nil
}

func (w *Workspace) Credentials(accountPub, userPub string) ([]byte, error) {
	a, ok := w.Accounts[accountPub]
	if !ok {
		return nil, errors.New("unknown account")
	}
	u, ok := a.Users[userPub]
	if !ok || u.Seed == "" {
		return nil, errors.New("user seed is unavailable")
	}
	return jwt.FormatUserConfig(u.JWT, []byte(u.Seed))
}

// AddExport and AddImport edit account JWT claims. The caller publishes the
// returned token and only then commits the encrypted workspace to KV.
func (w *Workspace) AddExport(accountPub, subject string, kind jwt.ExportType) (string, error) {
	return w.AddExportWithAccess(accountPub, subject, kind, false)
}

func (w *Workspace) AddExportWithAccess(accountPub, subject string, kind jwt.ExportType, private bool) (string, error) {
	return w.editAccount(accountPub, func(c *jwt.AccountClaims) error {
		if kind != jwt.Stream && kind != jwt.Service {
			return errors.New("export must be stream or service")
		}
		for _, e := range c.Exports {
			if e.Subject == jwt.Subject(subject) && e.Type == kind {
				return errors.New("export already exists")
			}
		}
		c.Exports = append(c.Exports, &jwt.Export{Subject: jwt.Subject(subject), Type: kind, TokenReq: private})
		return nil
	})
}

func (w *Workspace) AddImport(accountPub, fromPub, subject, localSubject string, kind jwt.ExportType) (string, error) {
	if _, ok := w.Accounts[fromPub]; !ok {
		return "", errors.New("exporting account must be managed")
	}
	if kind != jwt.Stream && kind != jwt.Service {
		return "", errors.New("import must be stream or service")
	}
	for _, e := range w.Accounts[fromPub].Exports() {
		if e.Subject == jwt.Subject(subject) && e.Type == kind {
			token := ""
			if e.TokenReq {
				pair, err := signer(w.Accounts[fromPub].Seed)
				if err != nil {
					return "", err
				}
				activation := jwt.NewActivationClaims(accountPub)
				activation.ImportSubject = jwt.Subject(subject)
				activation.ImportType = kind
				if err := validate(activation); err != nil {
					pair.Wipe()
					return "", err
				}
				token, err = activation.Encode(pair)
				pair.Wipe()
				if err != nil {
					return "", err
				}
			}
			return w.editAccount(accountPub, func(c *jwt.AccountClaims) error {
				for _, i := range c.Imports {
					if i.Account == fromPub && i.Subject == jwt.Subject(subject) && i.Type == kind {
						return errors.New("import already exists")
					}
				}
				c.Imports = append(c.Imports, &jwt.Import{Account: fromPub, Subject: jwt.Subject(subject), LocalSubject: jwt.RenamingSubject(localSubject), Type: kind, Token: token})
				return nil
			})
		}
	}
	return "", errors.New("no matching managed export")
}

func (a *Account) Exports() jwt.Exports {
	c, err := jwt.DecodeAccountClaims(a.JWT)
	if err != nil {
		return nil
	}
	return c.Exports
}

func (w *Workspace) editAccount(pub string, edit func(*jwt.AccountClaims) error) (string, error) {
	a, ok := w.Accounts[pub]
	if !ok {
		return "", fmt.Errorf("unknown account %s", pub)
	}
	c, err := jwt.DecodeAccountClaims(a.JWT)
	if err != nil {
		return "", err
	}
	if err := edit(c); err != nil {
		return "", err
	}
	if err := validate(c); err != nil {
		return "", err
	}
	operator, err := signer(w.OperatorSeed)
	if err != nil {
		return "", err
	}
	defer operator.Wipe()
	token, err := c.Encode(operator)
	if err == nil {
		a.JWT = token
	}
	return token, err
}
