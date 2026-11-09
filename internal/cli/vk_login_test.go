package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spaiter/spaiter-vpn/internal/vk"
)

// fakeTerminal answers the prompts from a script and records what was shown.
type fakeTerminal struct {
	in  *strings.Reader
	out bytes.Buffer
}

func (f *fakeTerminal) Read(p []byte) (int, error)  { return f.in.Read(p) }
func (f *fakeTerminal) Write(p []byte) (int, error) { return f.out.Write(p) }
func (f *fakeTerminal) Close() error                { return nil }

// vkLoginRig scripts the terminal and points the VK client at a stub.
func vkLoginRig(t *testing.T, typed string, handler http.HandlerFunc) *fakeTerminal {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	terminal := &fakeTerminal{in: strings.NewReader(typed)}

	oldOpen, oldClient, oldPass := openTerminal, newVKLoginClient, readPassphrase
	openTerminal = func() (io.ReadWriteCloser, error) {
		return terminal, nil
	}
	newVKLoginClient = func(c *vk.Client) *vk.Client {
		c.OAuthHost, c.APIHost = server.URL, server.URL
		return c
	}
	readPassphrase = func(prompt string) (string, error) {
		if strings.Contains(prompt, "secret") {
			return " app-secret \n", nil
		}
		return "hunter2", nil
	}
	t.Cleanup(func() { openTerminal, newVKLoginClient, readPassphrase = oldOpen, oldClient, oldPass })
	return terminal
}

func reply(w http.ResponseWriter, body string) { w.Write([]byte(body)) }

func TestVKLoginPrintsTheTokenAndKeepsItOffTheTerminalHistory(t *testing.T) {
	var asked []string
	terminal := vkLoginRig(t, "12345\n+49123\n", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		asked = append(asked, q.Get("client_id")+"|"+q.Get("client_secret")+"|"+q.Get("username")+"|"+q.Get("password"))
		reply(w, `{"access_token":"vk1.a.TOKEN","user_id":7}`)
	})
	var out bytes.Buffer
	if err := runVKLogin(context.Background(), &out, nil); err != nil {
		t.Fatal(err)
	}
	if len(asked) != 1 || asked[0] != "12345|app-secret|+49123|hunter2" {
		t.Errorf("VK was asked %v", asked)
	}
	var record map[string]string
	if err := json.Unmarshal(out.Bytes(), &record); err != nil || record["access_token"] != "vk1.a.TOKEN" || record["user_id"] != "7" || record["device_id"] == "" {
		t.Errorf("record = %s, %v", out.String(), err)
	}
	if !strings.Contains(terminal.out.String(), "signed in as user 7") || strings.Contains(terminal.out.String(), "vk1.a.TOKEN") {
		t.Errorf("terminal:\n%s", terminal.out.String())
	}
}

func TestVKLoginWritesAPrivateFileWhenAsked(t *testing.T) {
	vkLoginRig(t, "", func(w http.ResponseWriter, r *http.Request) {
		reply(w, `{"access_token":"vk1.a.TOKEN","user_id":7}`)
	})
	path := filepath.Join(t.TempDir(), "token.json")
	var out bytes.Buffer
	args := []string{"-app-id", "1", "-login", "me", "-device-id", "dev-1", "-o", path}
	if err := runVKLogin(context.Background(), &out, args); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("file = %v, %v", info, err)
	}
	if !strings.Contains(out.String(), "token written to "+path) {
		t.Errorf("output = %q", out.String())
	}
	bad := filepath.Join(t.TempDir(), "absent", "token.json")
	if err := runVKLogin(context.Background(), &out, []string{"-app-id", "1", "-login", "me", "-o", bad}); err == nil || !strings.Contains(err.Error(), "write") {
		t.Errorf("unwritable path: %v", err)
	}
}

func TestVKLoginAsksAgainAfterAWrongCode(t *testing.T) {
	terminal := vkLoginRig(t, "111\n222\n", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("code") {
		case "222":
			reply(w, `{"access_token":"vk1.a.TOKEN","user_id":7}`)
		default:
			reply(w, `{"error":"need_validation","validation_sid":"s","phone_mask":"+49 *** 12","validation_type":"2fa_sms"}`)
		}
	})
	var out bytes.Buffer
	if err := runVKLogin(context.Background(), &out, []string{"-app-id", "1", "-login", "me"}); err != nil {
		t.Fatal(err)
	}
	shown := terminal.out.String()
	for _, want := range []string{"VK sent a code to +49 *** 12 (2fa_sms)", "VK rejected that code", "signed in as user 7"} {
		if !strings.Contains(shown, want) {
			t.Errorf("terminal lacks %q:\n%s", want, shown)
		}
	}
}

func TestVKLoginTranslatesEachRefusal(t *testing.T) {
	cases := map[string]struct{ body, want string }{
		"a captcha":      {`{"error":"need_captcha","captcha_sid":"1","captcha_img":"https://vk.example/c.png"}`, "https://vk.example/c.png"},
		"a bad password": {`{"error":"invalid_client","error_description":"nope"}`, "rejected the login or password"},
		"an odd refusal": {`{"error":"too_many","error_description":"slow down"}`, "slow down"},
	}
	for name, tc := range cases {
		vkLoginRig(t, "", func(w http.ResponseWriter, r *http.Request) { reply(w, tc.body) })
		err := runVKLogin(context.Background(), &bytes.Buffer{}, []string{"-app-id", "1", "-login", "me"})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestVKLoginCanProveTheCallTokenPathInTheSameBreath(t *testing.T) {
	vkLoginRig(t, "", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/method/messages.getCallToken") {
			reply(w, `{"response":{"token":"CALL","api_base_url":"https://calls.example"}}`)
			return
		}
		reply(w, `{"access_token":"vk1.a.TOKEN","user_id":7}`)
	})
	var out bytes.Buffer
	if err := runVKLogin(context.Background(), &out, []string{"-app-id", "1", "-login", "me", "-mint"}); err != nil {
		t.Fatal(err)
	}
	var record map[string]string
	json.Unmarshal(out.Bytes(), &record)
	if record["call_token"] != "CALL" || record["api_base_url"] != "https://calls.example" {
		t.Errorf("record = %v", record)
	}

	vkLoginRig(t, "", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/method/") {
			reply(w, `{"error":{"error_code":5,"error_msg":"dead"}}`)
			return
		}
		reply(w, `{"access_token":"vk1.a.TOKEN","user_id":7}`)
	})
	if err := runVKLogin(context.Background(), &bytes.Buffer{}, []string{"-app-id", "1", "-login", "me", "-mint"}); err == nil {
		t.Error("a failed mint was reported as success")
	}
}

func TestVKLoginNeedsATerminalAndFailsWhenAPromptDoes(t *testing.T) {
	vkLoginRig(t, "", func(http.ResponseWriter, *http.Request) {})
	openTerminal = func() (io.ReadWriteCloser, error) {
		return nil, errors.New("no tty")
	}
	if err := runVKLogin(context.Background(), &bytes.Buffer{}, nil); err == nil || !strings.Contains(err.Error(), "needs a terminal") {
		t.Errorf("no terminal: %v", err)
	}

	vkLoginRig(t, "", func(http.ResponseWriter, *http.Request) {})
	readPassphrase = func(string) (string, error) { return "", errors.New("echo off failed") }
	if err := runVKLogin(context.Background(), &bytes.Buffer{}, []string{"-app-id", "1", "-login", "me"}); err == nil {
		t.Error("a failed secret prompt was ignored")
	}
}
