package masque

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"

	"github.com/spaiter/spaiter-vpn/core/option"
)

// Config is the account this outbound runs on, either minted by createConfig or
// handed to us whole via the `config` option. Same shape either way, so the
// cache file format is unaffected.
type Config option.MASQUEAccount

func (c *Config) GetEcPrivateKey() (*ecdsa.PrivateKey, error) {
	privKeyB64, err := base64.StdEncoding.DecodeString(c.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %v", err)
	}
	privKey, err := x509.ParseECPrivateKey(privKeyB64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}
	return privKey, nil
}

func (c *Config) GetEcEndpointPublicKey() (*ecdsa.PublicKey, error) {
	endpointPubKeyB64, _ := pem.Decode([]byte(c.EndpointPubKey))
	if endpointPubKeyB64 == nil {
		return nil, fmt.Errorf("failed to decode endpoint public key")
	}

	pubKey, err := x509.ParsePKIXPublicKey(endpointPubKeyB64.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	ecPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to assert public key as ECDSA")
	}

	return ecPubKey, nil
}

func (c *Config) SelectEndpointFromConfig(useHTTP2 bool, useIPv6 bool, port int) (net.Addr, error) {
	if useHTTP2 {
		if useIPv6 {
			if c.EndpointH2V6 == "" {
				return nil, fmt.Errorf("--http2 with --ipv6 requires config endpoint_h2_v6 to be set")
			}
			ip := net.ParseIP(c.EndpointH2V6)
			if ip == nil {
				return nil, fmt.Errorf("invalid endpoint_h2_v6 value %q", c.EndpointH2V6)
			}

			return &net.TCPAddr{IP: ip, Port: port}, nil
		}
		v4 := c.EndpointH2V4
		ip := net.ParseIP(v4)
		if ip == nil {
			return nil, fmt.Errorf("invalid endpoint_h2_v4 value %q", v4)
		}
		return &net.TCPAddr{IP: ip, Port: port}, nil
	}
	if useIPv6 {
		ip := net.ParseIP(c.EndpointV6)
		if ip == nil {
			return nil, fmt.Errorf("invalid endpoint_v6 value %q", c.EndpointV6)
		}
		return &net.UDPAddr{IP: ip, Port: port}, nil
	}
	ip := net.ParseIP(c.EndpointV4)
	if ip == nil {
		return nil, fmt.Errorf("invalid endpoint_v4 value %q", c.EndpointV4)
	}
	return &net.UDPAddr{IP: ip, Port: port}, nil
}
