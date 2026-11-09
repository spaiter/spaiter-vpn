//go:build !linux

package main

import "github.com/spaiter/spaiter-vpn/core/option"

func runInUserNamespaceIfNeeded(options option.Options, optionsList []*OptionsEntry) error {
	return nil
}
