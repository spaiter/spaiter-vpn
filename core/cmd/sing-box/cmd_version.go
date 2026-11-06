package main

import (
	"os"
	"runtime"
	"runtime/debug"

	C "github.com/spaiter/spaiter-vpn/core/constant"

	"github.com/spf13/cobra"
)

var commandVersion = &cobra.Command{
	Use:   "version",
	Short: "Print current version of sing-box",
	Run:   printVersion,
	Args:  cobra.NoArgs,
}

var nameOnly bool

func init() {
	commandVersion.Flags().BoolVarP(&nameOnly, "name", "n", false, "print version name only")
	mainCommand.AddCommand(commandVersion)
}

func printVersion(cmd *cobra.Command, args []string) {
	if nameOnly {
		os.Stdout.WriteString(C.Version + "\n")
		return
	}
	// Not the upstream name. sing-box's licence carries a clause beyond
	// GPL-3.0 forbidding derivative works from using its name or implying
	// association, and a binary announcing itself as "hiddify-sing-box" is
	// using it. Same reasoning that named the published image
	// spaiter-vpn-core. Factual attribution belongs in
	// THIRD-PARTY-NOTICES.md, which is where the GPL asks for it. //H
	version := "spaiter-vpn-core version " + C.Version + "\n\n"
	version += "Environment: " + runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH + "\n"

	var tags string
	var revision string

	debugInfo, loaded := debug.ReadBuildInfo()
	if loaded {
		for _, setting := range debugInfo.Settings {
			switch setting.Key {
			case "-tags":
				tags = setting.Value
			case "vcs.revision":
				revision = setting.Value
			}
		}
	}

	if tags != "" {
		version += "Tags: " + tags + "\n"
	}
	if revision != "" {
		version += "Revision: " + revision + "\n"
	}

	if C.CGO_ENABLED {
		version += "CGO: enabled\n"
	} else {
		version += "CGO: disabled\n"
	}

	os.Stdout.WriteString(version)
}
