//go:build !generate

package main

import "github.com/spaiter/spaiter-vpn/core/log"

func main() {
	if err := mainCommand.Execute(); err != nil {
		log.Fatal(err)
	}
}
