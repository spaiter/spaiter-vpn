package config

import "testing"

// Library callers can give one IP with several ports; each IP:port is a resolver of its own.
func TestParseResolverEntriesKeepsPortsOfOneIP(t *testing.T) {
	resolvers, resolverMap, err := ParseResolverEntries([]string{
		"127.0.0.1:5301", "127.0.0.1:5302", "127.0.0.1:5303", "127.0.0.1:5301", "8.8.8.8", "10.0.0.0/30:5300", "10.0.0.1:5300",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []ResolverAddress{
		{"10.0.0.1", 5300}, {"10.0.0.2", 5300},
		{"127.0.0.1", 5301}, {"127.0.0.1", 5302}, {"127.0.0.1", 5303},
		{"8.8.8.8", 53},
	}
	if len(resolvers) != len(want) {
		t.Fatalf("got %v, want %v", resolvers, want)
	}
	for i := range want {
		if resolvers[i] != want[i] {
			t.Fatalf("got %v, want %v", resolvers, want)
		}
	}
	if resolverMap["127.0.0.1"] != 5301 {
		t.Fatalf("resolverMap keeps the first port, got %d", resolverMap["127.0.0.1"])
	}
}

func TestParseResolverEntriesRejectsInvalid(t *testing.T) {
	if _, _, err := ParseResolverEntries([]string{"not-an-ip"}); err == nil {
		t.Fatal("want an error")
	}
	if _, _, err := ParseResolverEntries([]string{"# only a comment", ""}); err == nil {
		t.Fatal("want an error for no resolvers")
	}
}
