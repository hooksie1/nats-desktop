package views

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/thedataflows/nats-desktop/internal/accountmanager"
	"github.com/thedataflows/nats-desktop/internal/ui/components"
	"github.com/thedataflows/nats-desktop/internal/ui/theme"
)

type accountManagement struct {
	app        App
	manager    *accountmanager.Manager
	workspace  *accountmanager.Workspace
	passphrase string
	revision   uint64
	selected   string
	busy       bool
	generation uint64
	results    chan func()
	modal      *components.FormModal
	buttons    [9]widget.Clickable
	accounts   map[string]*widget.Clickable
	users      map[string]*widget.Clickable
}

func newAccountManagement(app App) *accountManagement {
	return &accountManagement{app: app, results: make(chan func(), 8), accounts: make(map[string]*widget.Clickable), users: make(map[string]*widget.Clickable)}
}

func (v *accountManagement) connected() (*nats.Conn, string, error) {
	client := v.app.GetNatsClient()
	if client == nil || !client.IsConnected() {
		return nil, "", errors.New("connect to the server with a system-account credential first")
	}
	return client.Conn(), client.Conn().ConnectedUrl(), nil
}

func (v *accountManagement) feedback(err error, message string) {
	if err != nil {
		v.app.ShowToast(err.Error(), components.ToastTypeError)
	} else {
		v.app.ShowToast(message, components.ToastTypeSuccess)
	}
	v.app.Invalidate()
}

func (v *accountManagement) work(fn func(context.Context) (func(), error), message string, discard ...func()) {
	if v.busy {
		return
	}
	v.busy = true
	generation := v.generation
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		apply, err := fn(ctx)
		v.results <- func() {
			v.busy = false
			if apply != nil && generation == v.generation {
				apply()
			} else if len(discard) != 0 && discard[0] != nil {
				discard[0]()
			}
			if generation == v.generation {
				v.feedback(err, message)
			}
		}
		v.app.Invalidate()
	}()
}

func (v *accountManagement) form(title string, fields []string, secret map[string]bool, action func(map[string]string)) {
	m := components.NewFormModal(title)
	m.MaxWidth = unit.Dp(620)
	m.SaveButtonText = "Continue"
	editors := make(map[string]*widget.Editor)
	for _, name := range fields {
		editor := &widget.Editor{SingleLine: true}
		editors[name] = editor
		m.Fields = append(m.Fields, components.FormField{Label: name, Editor: editor, Password: secret[name]})
	}
	m.OnSave = func() bool {
		values := make(map[string]string)
		for name, editor := range editors {
			values[name] = strings.TrimSpace(editor.Text())
			editor.SetText("")
		}
		action(values)
		return true
	}
	v.modal = m
	m.Show()
	v.app.Invalidate()
}

func (v *accountManagement) focusTags() []any {
	tags := make([]any, 0, 9+len(v.accounts)+len(v.users))
	for i := range v.buttons {
		tags = append(tags, &v.buttons[i])
	}
	if v.workspace == nil {
		return tags
	}
	accounts := make([]string, 0, len(v.workspace.Accounts))
	for pub := range v.workspace.Accounts {
		accounts = append(accounts, pub)
	}
	sort.Slice(accounts, func(i, j int) bool {
		return v.workspace.Accounts[accounts[i]].Name < v.workspace.Accounts[accounts[j]].Name
	})
	for _, pub := range accounts {
		if button := v.accounts[pub]; button != nil {
			tags = append(tags, button)
		}
	}
	if account := v.workspace.Accounts[v.selected]; account != nil {
		users := make([]string, 0, len(account.Users))
		for pub := range account.Users {
			users = append(users, pub)
		}
		sort.Slice(users, func(i, j int) bool { return account.Users[users[i]].Name < account.Users[users[j]].Name })
		for _, pub := range users {
			if button := v.users[pub]; button != nil {
				tags = append(tags, button)
			}
		}
	}
	return tags
}

func (v *accountManagement) newServer() {
	v.form("Generate external server configuration", []string{"Empty export directory", "Master passphrase"}, map[string]bool{"Master passphrase": true}, func(p map[string]string) {
		v.work(func(ctx context.Context) (func(), error) {
			b, err := accountmanager.NewBootstrap(p["Master passphrase"])
			if err != nil {
				return nil, err
			}
			if err := b.Write(p["Empty export directory"]); err != nil {
				return nil, err
			}
			return nil, nil
		}, "Server config and recovery exported; run from export directory. Configure TLS before exposing the loopback-only listener, then connect with system.creds and unlock")
	})
}

func (v *accountManagement) existingServer() {
	v.form("Initialize existing NATS-based resolver", []string{"Operator JWT", "Operator signing seed", "Empty recovery directory", "Master passphrase"}, map[string]bool{"Operator signing seed": true, "Master passphrase": true}, func(p map[string]string) {
		system, url, err := v.connected()
		if err != nil {
			v.feedback(err, "")
			return
		}
		var pending *accountmanager.Manager
		v.work(func(ctx context.Context) (func(), error) {
			m, w, _, err := accountmanager.OnboardExisting(ctx, system, p["Operator JWT"], p["Operator signing seed"], p["Master passphrase"], url, p["Empty recovery directory"])
			if err != nil {
				return nil, err
			}
			_, rev, err := m.Load(ctx, p["Master passphrase"])
			if err != nil {
				m.Close()
				return nil, err
			}
			pending = m
			return func() {
				if v.manager != nil {
					v.manager.Close()
				}
				v.manager = m
				v.workspace = w
				v.passphrase = p["Master passphrase"]
				v.revision = rev
				v.selected = ""
			}, nil
		}, "Management account published and encrypted workspace created", func() {
			if pending != nil {
				pending.Close()
			}
		})
	})
}

func (v *accountManagement) unlock() {
	v.form("Unlock identity workspace", []string{"Management credentials file", "Recovery export (only for first connection)", "Master passphrase"}, map[string]bool{"Master passphrase": true}, func(p map[string]string) {
		system, url, err := v.connected()
		if err != nil {
			v.feedback(err, "")
			return
		}
		var pending *accountmanager.Manager
		v.work(func(ctx context.Context) (func(), error) {
			m, w, rev, err := accountmanager.Connect(ctx, system, url, p["Management credentials file"], p["Master passphrase"], p["Recovery export (only for first connection)"])
			if err != nil {
				return nil, err
			}
			pending = m
			return func() {
				if v.manager != nil {
					v.manager.Close()
				}
				v.manager = m
				v.workspace = w
				v.passphrase = p["Master passphrase"]
				v.revision = rev
				v.selected = ""
			}, nil
		}, "Identity workspace unlocked", func() {
			if pending != nil {
				pending.Close()
			}
		})
	})
}

func (v *accountManagement) copyWorkspace() (*accountmanager.Workspace, error) {
	if v.workspace == nil {
		return nil, errors.New("unlock the workspace first")
	}
	data, err := json.Marshal(v.workspace)
	if err != nil {
		return nil, err
	}
	var w accountmanager.Workspace
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, err
	}
	return &w, nil
}

func (v *accountManagement) addAccount() {
	v.form("Create account", []string{"Account name"}, nil, func(p map[string]string) {
		w, err := v.copyWorkspace()
		if err != nil {
			v.feedback(err, "")
			return
		}
		revision, pass, m := v.revision, v.passphrase, v.manager
		v.work(func(ctx context.Context) (func(), error) {
			pub, token, err := w.CreateAccount(p["Account name"])
			if err != nil {
				return nil, err
			}
			rev, err := m.Apply(ctx, w, pass, revision, token)
			if err != nil {
				return nil, err
			}
			return func() { v.workspace = w; v.revision = rev; v.selected = pub }, nil
		}, "Account created and published")
	})
}

func (v *accountManagement) addUser() {
	pub := v.selected
	v.form("Create user in selected account", []string{"User name", "New credentials file"}, nil, func(p map[string]string) {
		w, err := v.copyWorkspace()
		if err != nil {
			v.feedback(err, "")
			return
		}
		revision, pass, m := v.revision, v.passphrase, v.manager
		v.work(func(ctx context.Context) (func(), error) {
			_, creds, err := w.CreateUser(pub, p["User name"])
			if err != nil {
				return nil, err
			}
			rev, err := m.Save(ctx, w, pass, revision)
			if err != nil {
				return nil, err
			}
			err = writePrivate(p["New credentials file"], creds)
			return func() { v.workspace = w; v.revision = rev }, err
		}, "User created; credentials exported")
	})
}

func writePrivate(path string, data []byte) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("choose a new file path")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func (v *accountManagement) addShare(isImport bool) {
	pub := v.selected
	title, fields := "Add export", []string{"Subject", "Type (stream or service)", "Access (public or private)"}
	if isImport {
		title, fields = "Add import", []string{"Exporting account public key", "Subject", "Local subject (optional)", "Type (stream or service)"}
	}
	v.form(title, fields, nil, func(p map[string]string) {
		w, err := v.copyWorkspace()
		if err != nil {
			v.feedback(err, "")
			return
		}
		revision, pass, m := v.revision, v.passphrase, v.manager
		v.work(func(ctx context.Context) (func(), error) {
			kind := jwt.Stream
			if strings.EqualFold(p["Type (stream or service)"], "service") {
				kind = jwt.Service
			} else if !strings.EqualFold(p["Type (stream or service)"], "stream") {
				return nil, errors.New("type must be stream or service")
			}
			var token string
			var err error
			if isImport {
				token, err = w.AddImport(pub, p["Exporting account public key"], p["Subject"], p["Local subject (optional)"], kind)
			} else {
				access := strings.ToLower(p["Access (public or private)"])
				if access != "public" && access != "private" {
					return nil, errors.New("access must be public or private")
				}
				token, err = w.AddExportWithAccess(pub, p["Subject"], kind, access == "private")
			}
			if err != nil {
				return nil, err
			}
			rev, err := m.Apply(ctx, w, pass, revision, token)
			if err != nil {
				return nil, err
			}
			return func() { v.workspace = w; v.revision = rev }, nil
		}, "Account JWT updated")
	})
}

func (v *accountManagement) exportUser(pub string) {
	user, account := pub, v.selected
	v.form("Export user credentials", []string{"New credentials file"}, nil, func(p map[string]string) {
		if v.workspace == nil {
			v.feedback(errors.New("unlock the workspace first"), "")
			return
		}
		creds, err := v.workspace.Credentials(account, user)
		if err == nil {
			err = writePrivate(p["New credentials file"], creds)
		}
		v.feedback(err, "Credentials exported")
	})
}

func (v *accountManagement) backup() {
	v.form("Export updated encrypted recovery", []string{"New recovery file"}, nil, func(p map[string]string) {
		w, err := v.copyWorkspace()
		if err != nil {
			v.feedback(err, "")
			return
		}
		pass := v.passphrase
		v.work(func(ctx context.Context) (func(), error) {
			data, err := accountmanager.Encrypt(w, pass)
			if err != nil {
				return nil, err
			}
			return nil, writePrivate(p["New recovery file"], data)
		}, "Updated recovery exported")
	})
}

func (v *accountManagement) layout(gtx layout.Context, th *theme.Theme) layout.Dimensions {
	if v.manager != nil {
		client := v.app.GetNatsClient()
		if client == nil || !client.IsConnected() || client.Conn() != v.manager.System {
			v.lock()
		}
	}
	for {
		select {
		case done := <-v.results:
			done()
		default:
			goto drained
		}
	}
drained:
	for v.buttons[0].Clicked(gtx) {
		if !v.busy {
			v.newServer()
		}
	}
	for v.buttons[1].Clicked(gtx) {
		if !v.busy {
			v.existingServer()
		}
	}
	for v.buttons[2].Clicked(gtx) {
		if !v.busy {
			v.unlock()
		}
	}
	for v.buttons[3].Clicked(gtx) {
		if !v.busy && v.workspace != nil {
			v.addAccount()
		}
	}
	for v.buttons[4].Clicked(gtx) {
		if !v.busy && v.selected != "" {
			v.addUser()
		}
	}
	for v.buttons[5].Clicked(gtx) {
		if !v.busy && v.selected != "" {
			v.addShare(false)
		}
	}
	for v.buttons[6].Clicked(gtx) {
		if !v.busy && v.selected != "" {
			v.addShare(true)
		}
	}
	for v.buttons[7].Clicked(gtx) {
		if !v.busy {
			v.lock()
		}
	}
	for v.buttons[8].Clicked(gtx) {
		if !v.busy && v.workspace != nil {
			v.backup()
		}
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(c layout.Context) layout.Dimensions {
			return material.H6(th.Material(), "Identity Management").Layout(c)
		}),
		layout.Rigid(func(c layout.Context) layout.Dimensions {
			return material.Body2(th.Material(), "Encrypted JetStream KV workspace; the NATS resolver serves signed account JWTs. Use TLS for remote servers and keep your recovery export safe.").Layout(c)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
		layout.Rigid(func(c layout.Context) layout.Dimensions { return v.actions(c, th) }),
		layout.Rigid(layout.Spacer{Height: unit.Dp(12)}.Layout),
		layout.Rigid(func(c layout.Context) layout.Dimensions { return v.entries(c, th) }),
	)
}

func (v *accountManagement) actions(gtx layout.Context, th *theme.Theme) layout.Dimensions {
	labels := []string{"New server config", "Existing server", "Unlock", "New account", "New user", "Add export", "Add import", "Lock", "Export recovery"}
	children := make([]layout.FlexChild, 0, len(labels)*2)
	for i, text := range labels {
		i, text := i, text
		children = append(children, layout.Rigid(func(c layout.Context) layout.Dimensions {
			return components.Button(th, &v.buttons[i], nil, 0, text).Layout(c, th)
		}))
		children = append(children, layout.Rigid(layout.Spacer{Width: unit.Dp(6)}.Layout))
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(c layout.Context) layout.Dimensions { return layout.Flex{}.Layout(c, children[:6]...) }),
		layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
		layout.Rigid(func(c layout.Context) layout.Dimensions { return layout.Flex{}.Layout(c, children[6:12]...) }),
		layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout),
		layout.Rigid(func(c layout.Context) layout.Dimensions { return layout.Flex{}.Layout(c, children[12:]...) }),
	)
}

func (v *accountManagement) lock() {
	v.generation++
	if v.manager != nil {
		v.manager.Close()
	}
	v.manager = nil
	v.workspace = nil
	v.passphrase = ""
	v.revision = 0
	v.selected = ""
}

func (v *accountManagement) entries(gtx layout.Context, th *theme.Theme) layout.Dimensions {
	if v.busy {
		return material.Body1(th.Material(), "Working…").Layout(gtx)
	}
	if v.workspace == nil {
		return material.Body1(th.Material(), "Generate a server configuration, initialize an existing server, or unlock a workspace to manage identities.").Layout(gtx)
	}
	keys := make([]string, 0, len(v.workspace.Accounts))
	for pub := range v.workspace.Accounts {
		keys = append(keys, pub)
	}
	sort.Slice(keys, func(i, j int) bool { return v.workspace.Accounts[keys[i]].Name < v.workspace.Accounts[keys[j]].Name })
	children := make([]layout.FlexChild, 0, len(keys)*2)
	for _, pub := range keys {
		pub := pub
		a := v.workspace.Accounts[pub]
		if v.accounts[pub] == nil {
			v.accounts[pub] = &widget.Clickable{}
		}
		for v.accounts[pub].Clicked(gtx) {
			v.selected = pub
		}
		name := fmt.Sprintf("%s  %s  (%d users)", a.Name, pub, len(a.Users))
		if pub == v.selected {
			name = "▸ " + name
		}
		children = append(children, layout.Rigid(func(c layout.Context) layout.Dimensions {
			return components.Button(th, v.accounts[pub], nil, 0, name).Layout(c, th)
		}))
		children = append(children, layout.Rigid(layout.Spacer{Height: unit.Dp(6)}.Layout))
	}
	if a := v.workspace.Accounts[v.selected]; a != nil {
		children = append(children, layout.Rigid(func(c layout.Context) layout.Dimensions {
			return material.Body2(th.Material(), fmt.Sprintf("Selected: %d exports, %d imports. Select a user to export credentials.", len(a.Exports()), lenImports(a.JWT))).Layout(c)
		}))
		userKeys := make([]string, 0, len(a.Users))
		for pub := range a.Users {
			userKeys = append(userKeys, pub)
		}
		sort.Slice(userKeys, func(i, j int) bool { return a.Users[userKeys[i]].Name < a.Users[userKeys[j]].Name })
		for _, pub := range userKeys {
			pub, user := pub, a.Users[pub]
			if v.users[pub] == nil {
				v.users[pub] = &widget.Clickable{}
			}
			for v.users[pub].Clicked(gtx) {
				v.exportUser(pub)
			}
			children = append(children, layout.Rigid(func(c layout.Context) layout.Dimensions {
				return components.Button(th, v.users[pub], nil, 0, "Export creds: "+user.Name+" "+pub).Layout(c, th)
			}))
		}
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
}

func lenImports(token string) int {
	c, err := jwt.DecodeAccountClaims(token)
	if err != nil {
		return 0
	}
	return len(c.Imports)
}
