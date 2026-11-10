package vless

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/option"
)

// The reload swaps the user snapshot while connection handlers are resolving
// indexes against it. Run both concurrently under -race, and assert the
// bounds check holds when the list grows underneath a reader.
func TestUserNameConcurrentWithSwap(t *testing.T) {
	h := &Inbound{}
	initial := []option.VLESSUser{{Name: "alice", UUID: "u1"}}
	h.users.Store(&initial)

	var stop atomic.Bool
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			// Index 1 is out of range until the swap lands; must never panic.
			_ = h.userName(0)
			_ = h.userName(1)
			_ = h.userName(99)
			_ = h.userName(-1)
		}
	}()

	for i := 0; i < 2000; i++ {
		grown := []option.VLESSUser{{Name: "alice", UUID: "u1"}, {Name: "bob", UUID: "u2"}}
		h.users.Store(&grown)
		shrunk := []option.VLESSUser{{Name: "alice", UUID: "u1"}}
		h.users.Store(&shrunk)
	}
	stop.Store(true)
	wg.Wait()

	if got := h.userName(0); got != "alice" {
		t.Fatalf("userName(0) = %q", got)
	}
	if got := h.userName(1); got != "" {
		t.Fatalf("out-of-range index must yield empty name, got %q", got)
	}
}

// A nil snapshot is reachable before the constructor stores one.
func TestUserNameBeforeInit(t *testing.T) {
	h := &Inbound{}
	if got := h.userName(0); got != "" {
		t.Fatalf("got %q", got)
	}
}

// apply hands over whatever the inbound registry built, and that is a POINTER
// to the options struct (adapter/inbound.Register does `new(Options)`).
// Accepting only the value shape makes every reload fail with "unexpected
// options type" and silently degrade to recreating the inbound.
func TestReloadUsersAcceptsRegistryOptionsShape(t *testing.T) {
	h := &Inbound{}
	initial := []option.VLESSUser{{Name: "alice", UUID: "u1"}}
	h.users.Store(&initial)

	err := h.ReloadUsers(&option.VLESSInboundOptions{Users: initial})
	if err != nil {
		t.Fatalf("pointer options must be accepted, got %v", err)
	}
	if err := h.ReloadUsers(option.VLESSInboundOptions{Users: initial}); err == nil {
		t.Fatal("value options are not what the registry produces; must be rejected")
	}
}

func TestReloadUsersRejectsNonAppend(t *testing.T) {
	h := &Inbound{}
	initial := []option.VLESSUser{{Name: "alice", UUID: "u1"}, {Name: "bob", UUID: "u2"}}
	h.users.Store(&initial)

	// Dropping bob shifts no index here, but removing alice would shift bob's;
	// either way an in-place swap is unsafe and must be refused.
	err := h.ReloadUsers(&option.VLESSInboundOptions{
		Users: []option.VLESSUser{{Name: "bob", UUID: "u2"}},
	})
	if err == nil {
		t.Fatal("a non-append user list must be refused so the caller recreates")
	}
}
