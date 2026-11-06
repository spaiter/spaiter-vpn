package main

import (
	"io"
	"net"
	"os"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	C "github.com/spaiter/spaiter-vpn/core/constant"
	"github.com/spaiter/spaiter-vpn/core/log"
	"github.com/spaiter/spaiter-vpn/core/option"

	"github.com/oschwald/maxminddb-golang"
	"github.com/spf13/cobra"
)

var flagGeoipExportOutput string

const flagGeoipExportDefaultOutput = "geoip-<country>.srs"

var commandGeoipExport = &cobra.Command{
	Use:   "export <country>",
	Short: "Export geoip country as rule-set",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		err := geoipExport(args[0])
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	commandGeoipExport.Flags().StringVarP(&flagGeoipExportOutput, "output", "o", flagGeoipExportDefaultOutput, "Output path")
	commandGeoip.AddCommand(commandGeoipExport)
}

func geoipExport(countryCode string) error {
	networks := geoipReader.Networks(maxminddb.SkipAliasedNetworks)
	countryMap := make(map[string][]*net.IPNet)
	var (
		ipNet           *net.IPNet
		nextCountryCode string
		err             error
	)
	for networks.Next() {
		ipNet, err = networks.Network(&nextCountryCode)
		if err != nil {
			return err
		}
		countryMap[nextCountryCode] = append(countryMap[nextCountryCode], ipNet)
	}
	ipNets := countryMap[strings.ToLower(countryCode)]
	if len(ipNets) == 0 {
		return E.New("country code not found: ", countryCode)
	}

	var (
		outputFile   *os.File
		outputWriter io.Writer
	)
	switch flagGeoipExportOutput {
	case "stdout":
		outputWriter = os.Stdout
	case flagGeoipExportDefaultOutput:
		outputFile, err = os.Create("geoip-" + countryCode + ".json")
		if err != nil {
			return err
		}
		defer outputFile.Close()
		outputWriter = outputFile
	default:
		outputFile, err = os.Create(flagGeoipExportOutput)
		if err != nil {
			return err
		}
		defer outputFile.Close()
		outputWriter = outputFile
	}

	encoder := json.NewEncoder(outputWriter)
	encoder.SetIndent("", "  ")
	var headlessRule option.DefaultHeadlessRule
	headlessRule.IPCIDR = make([]string, 0, len(ipNets))
	for _, cidr := range ipNets {
		headlessRule.IPCIDR = append(headlessRule.IPCIDR, cidr.String())
	}
	var plainRuleSet option.PlainRuleSetCompat
	plainRuleSet.Version = C.RuleSetVersion2
	plainRuleSet.Options.Rules = []option.HeadlessRule{
		{
			Type:           C.RuleTypeDefault,
			DefaultOptions: headlessRule,
		},
	}
	return encoder.Encode(plainRuleSet)
}
