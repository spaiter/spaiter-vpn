package cli

import (
	"bytes"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	botcfg "github.com/spaiter/spaiter-vpn/internal/bot"
	"github.com/spaiter/spaiter-vpn/internal/bot/state"
)

func TestBotClaimCodeIssuesAWorkingOneShotCode(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	if err := runBotClaimCode(&out, []string{"-data-dir", dir, "-ttl", "10m"}); err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`claim code: (\S+)`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("no code in:\n%s", out.String())
	}
	for _, want := range []string{"/claim " + m[1], "10m0s", "works once", "wrong attempts destroy it"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "already has") {
		t.Error("claimed a pre-existing admin on a fresh bot")
	}

	// The printed code really adopts the bot, once.
	store, err := state.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := store.Claim("not-the-code", 7, time.Now()); ok || err != nil {
		t.Fatalf("a wrong code: %v %v", ok, err)
	}
	if ok, err := store.Claim(m[1], 42, time.Now()); !ok || err != nil {
		t.Fatalf("the printed code did not work: %v %v", ok, err)
	}
	if ok, _ := store.Claim(m[1], 43, time.Now()); ok {
		t.Error("a claim code worked twice")
	}

	// A bot that already has an admin says so, since this adds another.
	out.Reset()
	if err := runBotClaimCode(&out, []string{"-data-dir", dir}); err != nil || !strings.Contains(out.String(), "already has 1 admin") {
		t.Errorf("second code: %v\n%s", err, out.String())
	}
}

func TestBotClaimCodeRefusesUnreasonableLifetimes(t *testing.T) {
	for _, args := range [][]string{
		{"-ttl", "0s"}, {"-ttl", "-5m"}, {"-ttl", "25h"}, {"stray"},
	} {
		err := runBotClaimCode(&bytes.Buffer{}, append([]string{"-data-dir", t.TempDir()}, args...))
		if !errors.Is(err, ErrUsage) {
			t.Errorf("%v: %v, want ErrUsage", args, err)
		}
	}
}

func TestDescribeBotConfigNamesTheTokenGapNotItsValue(t *testing.T) {
	var cfg botcfg.Config
	cfg.Core.ConfigPath = "/etc/core/config.json"
	cfg.Public.Host = "vpn.example.org"
	cfg.Subscription.Port = 8080
	cfg.Admins = []int64{1, 2}

	t.Setenv("TELEGRAM_TOKEN", "")
	var out bytes.Buffer
	if err := describeBotConfig(&out, cfg); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/etc/core/config.json", "vpn.example.org", ":8080", "[1 2]", "TELEGRAM_TOKEN is not set"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}

	t.Setenv("TELEGRAM_TOKEN", "123456:SECRET-TOKEN-VALUE")
	out.Reset()
	describeBotConfig(&out, cfg)
	if strings.Contains(out.String(), "SECRET-TOKEN-VALUE") || strings.Contains(out.String(), "TELEGRAM_TOKEN is not set") {
		t.Errorf("a set token must be neither printed nor reported missing:\n%s", out.String())
	}
}
