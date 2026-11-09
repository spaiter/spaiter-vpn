package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestEveryVKSubcommandExplainsItselfOnHelp(t *testing.T) {
	for _, sub := range []string{"login", "mint", "holder", "relogin"} {
		var out bytes.Buffer
		err := runVK(context.Background(), &out, []string{sub, "-h"})
		if err == nil {
			t.Errorf("%s -h reported success", sub)
		}
		if !strings.Contains(out.String(), "usage: ") || !strings.Contains(out.String(), "vk "+sub) {
			t.Errorf("%s -h printed:\n%s", sub, out.String())
		}
	}
}

func TestVKMintRefusesAnUnreadableStdin(t *testing.T) {
	stdinHolds(t, "")
	if err := runVKMint(context.Background(), &bytes.Buffer{}, nil); err == nil {
		t.Error("an empty stdin produced a token")
	}
}
