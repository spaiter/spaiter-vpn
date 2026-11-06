package adapter

// Applying a config change by tearing the inbound down and building it again
// drops every live connection on it. These two interfaces let a component take
// the common case — a user or peer was added — without that disruption; the
// caller falls back to recreate when the component does not implement them or
// when more than the user/peer list changed. //H
type (
	// UserReloader swaps an inbound's user list on the running service.
	// options is the same typed options struct the inbound was created with.
	UserReloader interface {
		ReloadUsers(options any) error
	}

	// PeerReloader swaps an endpoint's peer list in place. For WireGuard this
	// is incremental: untouched peers keep their session and handshake.
	PeerReloader interface {
		ReloadPeers(options any) error
	}
)

// UsersAppendOnly reports whether next is old with users appended and nothing
// else touched.
//
// Inbounds authenticate a connection to a user *index* and only look the name
// up later, from the handler. Swapping in a list that reorders or drops entries
// would leave in-flight connections holding an index into the old list: at best
// the traffic gets attributed to the wrong user, at worst the index is past the
// end of the new list. An append keeps every existing index meaning exactly
// what it meant, which makes the swap safe without pausing the inbound. Any
// other edit returns false, and the caller recreates the inbound instead. //H
func UsersAppendOnly[T comparable](old, next []T) bool {
	if len(next) < len(old) {
		return false
	}
	for i := range old {
		if old[i] != next[i] {
			return false
		}
	}
	return true
}
