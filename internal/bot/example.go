package bot

// ExampleConfig is Defaults with the hosts a deployment has to supply filled
// in from example.com, as in the documentation. Tests use it; a real bot gets
// its hosts from its configuration file.
func ExampleConfig() Config {
	c := Defaults()
	c.Public.Host = "vpn.example.com"
	c.Public.IPv4Host = "vpn4.example.com"
	c.Public.CDN = map[string]CDNFront{
		"vless-ws-cdn-in": {Host: "cdn.example.com", Port: 443, SNI: "cdn.example.com"},
	}
	c.Subscription.HostCF = "sub.example.com"
	c.Subscription.HostDirect = "subd.example.com:10866"
	return c
}
