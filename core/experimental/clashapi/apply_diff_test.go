package clashapi

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// diffOptions has to see the protocol's own settings, which live behind an
// `Options any` field that only the pointer-receiver marshaller folds in.
// Marshalling by value yields just {"type","tag"}, so every entry compares
// equal and apply becomes a silent no-op — the bug this guards.
// Marshalling needs no registry — option.Inbound only consults one when
// decoding, to pick the per-protocol options type.
func testContext() context.Context {
	return context.Background()
}

func inboundWithUsers(tag string, users ...option.VLESSUser) option.Inbound {
	return option.Inbound{
		Type: "vless",
		Tag:  tag,
		Options: option.VLESSInboundOptions{
			Users: users,
		},
	}
}

func TestDiffOptionsSeesNestedOptions(t *testing.T) {
	ctx := testContext()
	alice := option.VLESSUser{Name: "alice", UUID: "11111111-1111-1111-1111-111111111111"}
	bob := option.VLESSUser{Name: "bob", UUID: "22222222-2222-2222-2222-222222222222"}

	have := inboundWithUsers("in", alice)
	want := inboundWithUsers("in", alice, bob)

	// Sanity-check the premise: by value the nested options vanish.
	byValue, err := json.MarshalContext(ctx, have)
	require.NoError(t, err)
	assert.NotContains(t, string(byValue), "alice", "value marshalling drops nested options")
	byPointer, err := json.MarshalContext(ctx, &have)
	require.NoError(t, err)
	assert.Contains(t, string(byPointer), "alice")

	changed, usersOnly, err := diffOptions(ctx, have, want, "users")
	require.NoError(t, err)
	assert.True(t, changed, "an added user must register as a change")
	assert.True(t, usersOnly, "only the user list differs")
}

func TestDiffOptionsIdentical(t *testing.T) {
	ctx := testContext()
	alice := option.VLESSUser{Name: "alice", UUID: "11111111-1111-1111-1111-111111111111"}
	have := inboundWithUsers("in", alice)

	changed, _, err := diffOptions(ctx, have, inboundWithUsers("in", alice), "users")
	require.NoError(t, err)
	assert.False(t, changed)
}

func TestDiffOptionsBeyondUsers(t *testing.T) {
	ctx := testContext()
	alice := option.VLESSUser{Name: "alice", UUID: "11111111-1111-1111-1111-111111111111"}

	have := inboundWithUsers("in", alice)
	want := option.Inbound{
		Type: "vless",
		Tag:  "in",
		Options: option.VLESSInboundOptions{
			Users:         []option.VLESSUser{alice},
			ListenOptions: option.ListenOptions{ListenPort: 1080},
		},
	}

	// A changed port must not be mistaken for a user-only edit, or it would be
	// swallowed by the in-place reload and never take effect.
	changed, usersOnly, err := diffOptions(ctx, have, want, "users")
	require.NoError(t, err)
	assert.True(t, changed)
	assert.False(t, usersOnly)
}

func TestObjectWithoutRemovesKey(t *testing.T) {
	out, err := objectWithout([]byte(`{"a":1,"users":[{"n":"x"}],"b":2}`), "users")
	require.NoError(t, err)
	assert.NotContains(t, string(out), "users")
	assert.Contains(t, string(out), `"a":1`)

	// Key ordering must not matter: the comparison relies on normalisation.
	one, err := objectWithout([]byte(`{"a":1,"b":2}`), "users")
	require.NoError(t, err)
	two, err := objectWithout([]byte(`{"b":2,"a":1}`), "users")
	require.NoError(t, err)
	assert.Equal(t, string(one), string(two))

	_, err = objectWithout([]byte(`["not","an","object"]`), "users")
	assert.Error(t, err)
}
