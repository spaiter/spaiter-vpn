//go:build with_xdp && linux

package xdp

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureLogger records Info lines so the block message can be asserted on.
type captureLogger struct {
	log.ContextLogger
	mu    sync.Mutex
	lines []string
}

func (c *captureLogger) Info(args ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var b strings.Builder
	for _, a := range args {
		b.WriteString(sprint(a))
	}
	c.lines = append(c.lines, b.String())
}

func (c *captureLogger) InfoContext(_ context.Context, args ...any) { c.Info(args...) }

func sprint(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case netip.Addr:
		return t.String()
	case time.Duration:
		return t.String()
	default:
		return fmt.Sprint(t)
	}
}

// The Grafana exporter parses these lines with
//
//	XDP blocked \S+ user=(\S+)
//
// so the exact shape of the message is a contract with it, not cosmetics:
// drop or reorder the user= field and per-user block metrics silently go to
// the "-" bucket forever. //H
func TestBlockIPLogFormatCarriesUser(t *testing.T) {
	cap := &captureLogger{ContextLogger: nopLogger()}
	// No filters: AddIP is skipped, but the logging path is the same one the
	// real service takes after a successful block.
	s := &Service{logger: cap, logBlocked: true, banDuration: time.Minute}

	require.NoError(t, s.BlockIP(netip.MustParseAddr("203.0.113.7"), time.Minute, "alice"))
	require.Len(t, cap.lines, 1)
	line := cap.lines[0]
	assert.Contains(t, line, "XDP blocked 203.0.113.7 user=alice for ")
	assert.Contains(t, line, "(total: ")

	// Unattributed traffic must still emit the field, so the format stays
	// uniform and the exporter's regex keeps matching.
	cap.lines = nil
	require.NoError(t, s.BlockIP(netip.MustParseAddr("203.0.113.8"), time.Minute, ""))
	require.Len(t, cap.lines, 1)
	assert.Contains(t, cap.lines[0], "user=- for ")
}
