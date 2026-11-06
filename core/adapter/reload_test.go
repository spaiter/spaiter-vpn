package adapter

import "testing"

func TestUsersAppendOnly(t *testing.T) {
	type user struct{ Name, Secret string }
	a := user{"alice", "a"}
	b := user{"bob", "b"}
	c := user{"carol", "c"}

	for _, tc := range []struct {
		name      string
		old, next []user
		want      bool
	}{
		{"append one", []user{a}, []user{a, b}, true},
		{"append several", []user{a}, []user{a, b, c}, true},
		{"unchanged", []user{a, b}, []user{a, b}, true},
		{"from empty", nil, []user{a}, true},
		// A removal shifts every later index, so an in-flight connection
		// authenticated as index 1 would resolve to a different user.
		{"removal", []user{a, b}, []user{a}, false},
		{"reorder", []user{a, b}, []user{b, a}, false},
		// Same length, but the credential at index 0 changed.
		{"edit in place", []user{a, b}, []user{{"alice", "new"}, b}, false},
		{"replace all", []user{a}, []user{b, c}, false},
		{"emptied", []user{a}, nil, false},
	} {
		if got := UsersAppendOnly(tc.old, tc.next); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
