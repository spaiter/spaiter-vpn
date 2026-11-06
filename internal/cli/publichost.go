package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/bootstrap/state"
)

// Seams for tests: this machine's addresses, and the resolver a domain is
// checked against.
var (
	localAddrs = interfaceAddrs
	lookupHost = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}
)

// cgnat is RFC 6598 shared address space: a carrier's NAT, not a public address.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// interfaceAddrs returns the addresses on this machine that the internet can
// reach directly. A VPS usually has its public IPv4 on an interface; a server
// at home has only private ones, and its public address is the router's.
func interfaceAddrs() []netip.Addr {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var public []netip.Addr
	for _, a := range addrs {
		prefix, err := netip.ParsePrefix(a.String())
		if err != nil {
			continue
		}
		ip := prefix.Addr().Unmap()
		if ip.IsGlobalUnicast() && !ip.IsPrivate() && !cgnat.Contains(ip) {
			public = append(public, ip)
		}
	}
	return public
}

// preferredAddr picks the address to hand clients: IPv4 when there is one,
// because VK's TURN and several clients' UDP paths are IPv4-only.
func preferredAddr(addrs []netip.Addr) (netip.Addr, bool) {
	for _, a := range addrs {
		if a.Is4() {
			return a, true
		}
	}
	if len(addrs) > 0 {
		return addrs[0], true
	}
	return netip.Addr{}, false
}

// publicAddress is what clients are told to dial, whether it can change, and
// the updater that keeps a changing one's record, if one was chosen.
type publicAddress struct {
	host    string
	dynamic bool
	ddns    *state.DDNS
}

// ddnsCredential is the credential name the updater's token is stored under.
const ddnsCredential = "ddns-token"

// choosePublicAddress asks how clients will reach this server.
//
// A dynamic address needs a domain kept current by dynamic DNS: a client
// config holding the address itself stops working the first time it changes,
// and every user would need a new one. A static address can be used as it is,
// with a domain optional.
//
// given is -public-host and dynamicGiven -dynamic-ip; with no terminal they
// are the whole answer, and with neither the address is left for the operator
// to fill in.
//
// offerDDNS asks, for a dynamic address, whether this server should keep the
// record itself; only bootstrap can install the updater.
func choosePublicAddress(ctx context.Context, in *bufio.Reader, out io.Writer, given string, dynamicGiven, offerDDNS bool) (publicAddress, error) {
	if given != "" {
		if err := checkPublicHost(given, dynamicGiven); err != nil {
			return publicAddress{}, err
		}
		warnIfNotHere(ctx, out, given)
		return publicAddress{host: given, dynamic: dynamicGiven}, nil
	}
	if in == nil {
		if dynamicGiven {
			return publicAddress{}, fmt.Errorf("%w: -dynamic-ip needs -public-host: a server whose address changes is reached by a domain", ErrUsage)
		}
		fmt.Fprintf(out, "No -public-host given: set bot.publicHost to the address clients should dial.\n")
		return publicAddress{}, nil
	}

	detected, found := preferredAddr(localAddrs())
	if found {
		fmt.Fprintf(out, "This server's public address: %s\n", detected)
	} else {
		fmt.Fprintf(out, "This server has no public address of its own: it is behind NAT, and\n"+
			"clients reach it through the router's address, with ports forwarded.\n")
	}
	fmt.Fprintf(out, "A VPS usually has a static address; a home connection usually a dynamic one.\n")
	// Behind NAT the default is dynamic, because that is nearly always a home line.
	prompt, staticDefault := "Is the public IP address static? [Y/n] ", true
	if !found {
		prompt, staticDefault = "Is the public IP address static? [y/N] ", false
	}
	answer, err := ask(in, out, prompt)
	if err != nil {
		return publicAddress{}, err
	}
	static := staticDefault
	switch strings.ToLower(answer) {
	case "y", "yes":
		static = true
	case "n", "no":
		static = false
	}

	if !static {
		fmt.Fprintf(out, "\nA dynamic address needs a domain with automatic DNS updates (dynamic DNS):\n"+
			"clients are given the domain, and the record must follow the address every\n"+
			"time it changes. Set that up with your DNS provider or router (ddclient,\n"+
			"the provider's DDNS client, or the router's DynDNS); a config holding the\n"+
			"address itself stops working the first time it changes.\n")
		for attempt := 0; attempt < 5; attempt++ {
			host, err := ask(in, out, "Domain clients will use: ")
			if err != nil {
				return publicAddress{}, err
			}
			if err := checkPublicHost(host, true); err != nil {
				fmt.Fprintf(out, "  %v\n", err)
				continue
			}
			warnIfNotHere(ctx, out, host)
			address := publicAddress{host: host, dynamic: true}
			if offerDDNS {
				d, err := askDDNS(in, out, host)
				if err != nil {
					return publicAddress{}, err
				}
				address.ddns = d
			} else {
				fmt.Fprintf(out, "`spaiter-vpn bootstrap` can keep the record itself (Cloudflare, DuckDNS, dyndns2).\n")
			}
			return address, nil
		}
		return publicAddress{}, fmt.Errorf("%w: a dynamic address needs a domain, and none was given", ErrUsage)
	}

	for attempt := 0; attempt < 5; attempt++ {
		var host string
		if found {
			host, err = ask(in, out, fmt.Sprintf("Domain for client configs (optional; Enter uses %s): ", detected))
		} else {
			host, err = ask(in, out, "Public IP address or domain for client configs: ")
		}
		if err != nil {
			return publicAddress{}, err
		}
		if host == "" && found {
			host = detected.String()
		} else if err := checkPublicHost(host, false); err != nil {
			fmt.Fprintf(out, "  %v\n", err)
			continue
		}
		warnIfNotHere(ctx, out, host)
		if _, err := netip.ParseAddr(host); err == nil {
			fmt.Fprintf(out, "Note: without a domain, moving to another server later means every user\n"+
				"has to import the subscription again; with one the move goes unnoticed.\n")
		}
		return publicAddress{host: host}, nil
	}
	return publicAddress{}, fmt.Errorf("%w: no usable public address was given", ErrUsage)
}

// checkPublicHost accepts a bare IP address or host name. A dynamic address
// must be a name: an address literal is exactly what stops working.
func checkPublicHost(host string, dynamic bool) error {
	if host == "" {
		return fmt.Errorf("empty")
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if dynamic {
			return fmt.Errorf("%s is an IP address; a dynamic one needs a domain", host)
		}
		if !ip.IsGlobalUnicast() || ip.IsPrivate() || cgnat.Contains(ip) {
			return fmt.Errorf("%s is not a public address; clients on the internet cannot reach it", host)
		}
		return nil
	}
	if strings.ContainsAny(host, ":/ @") || strings.Trim(host, ".") != host || !strings.Contains(host, ".") {
		return fmt.Errorf("%q is neither an IP address nor a domain like vpn.example.com", host)
	}
	return nil
}

// warnIfNotHere resolves a domain and says so when it does not point at this
// server. Only a warning: the record may be about to be created, and a server
// behind NAT never sees its own public address.
func warnIfNotHere(ctx context.Context, out io.Writer, host string) {
	if _, err := netip.ParseAddr(host); err == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	resolved, err := lookupHost(ctx, host)
	if err != nil || len(resolved) == 0 {
		fmt.Fprintf(out, "Note: %s does not resolve yet; clients will need it to.\n", host)
		return
	}
	local := localAddrs()
	if len(local) == 0 {
		return
	}
	for _, r := range resolved {
		for _, l := range local {
			if r.Unmap() == l {
				return
			}
		}
	}
	fmt.Fprintf(out, "Note: %s resolves to %s, not to this server.\n", host, resolved[0])
}

// askDDNS offers the built-in updater for a dynamic address's domain.
func askDDNS(in *bufio.Reader, out io.Writer, host string) (*state.DDNS, error) {
	fmt.Fprintf(out, "\nThis server can keep %s on its address itself, checking every 5 minutes.\n", host)
	suggested := "cloudflare"
	if strings.HasSuffix(host, ".duckdns.org") {
		suggested = "duckdns"
	}
	for attempt := 0; attempt < 5; attempt++ {
		answer, err := ask(in, out, fmt.Sprintf("DNS provider: cloudflare, duckdns, dyndns2 (No-IP, Dynu, ...) or none [%s]: ", suggested))
		if err != nil {
			return nil, err
		}
		provider := strings.ToLower(answer)
		if provider == "" {
			provider = suggested
		}
		d := &state.DDNS{Provider: provider, Token: ddnsCredential}
		switch provider {
		case "none":
			fmt.Fprintf(out, "Keep the record updated another way: the router's DynDNS, ddclient or the provider's client.\n")
			return nil, nil
		case "cloudflare":
			answer, err := ask(in, out, "Also keep an AAAA record for IPv6? [y/N] ")
			if err != nil {
				return nil, err
			}
			d.IPv6 = strings.EqualFold(answer, "y") || strings.EqualFold(answer, "yes")
			fmt.Fprintf(out, "The token needs Zone:DNS:Edit on the zone of %s.\n", host)
		case "duckdns":
			if !strings.HasSuffix(host, ".duckdns.org") {
				fmt.Fprintf(out, "  DuckDNS keeps *.duckdns.org names, and %s is not one\n", host)
				continue
			}
		case "dyndns2":
			server, err := ask(in, out, "Update service URL (e.g. https://dynupdate.no-ip.com): ")
			if err != nil {
				return nil, err
			}
			username, err := ask(in, out, "Username: ")
			if err != nil {
				return nil, err
			}
			if !strings.HasPrefix(server, "https://") || username == "" {
				fmt.Fprintf(out, "  dyndns2 needs an https URL and a username\n")
				continue
			}
			d.Server, d.Username = strings.TrimRight(server, "/"), username
		default:
			fmt.Fprintf(out, "  unknown provider %q\n", answer)
			continue
		}
		fmt.Fprintf(out, "Store the token (dyndns2: the password) before applying:\n  sudo spaiter-vpn bootstrap credential %s\n", ddnsCredential)
		return d, nil
	}
	return nil, fmt.Errorf("%w: no usable DNS provider was chosen", ErrUsage)
}
