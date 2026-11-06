//go:build with_acme

package include

import (
	"github.com/spaiter/spaiter-vpn/core/adapter/certificate"
	"github.com/spaiter/spaiter-vpn/core/service/acme"
)

func registerACMECertificateProvider(registry *certificate.Registry) {
	acme.RegisterCertificateProvider(registry)
}
