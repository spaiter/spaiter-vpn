package main

import (
	"context"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/hiddify/hinvalid"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"

	"github.com/spf13/cobra"
)

var commandCheck = &cobra.Command{
	Use:   "check",
	Short: "Check configuration",
	Run: func(cmd *cobra.Command, args []string) {
		err := check()
		if err != nil {
			log.Fatal(err)
		}
	},
	Args: cobra.NoArgs,
}

func init() {
	mainCommand.AddCommand(commandCheck)
}

func check() error {
	options, err := readConfigAndMerge()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(service.ExtendContext(globalCtx))
	defer cancel()
	return checkOptions(ctx, options)
}

// checkOptions builds the instance and refuses a config the running service
// would only half load. box.New keeps a broken outbound or endpoint as an
// invalid placeholder so that one bad entry does not take the rest down, and
// fails only when every real one is broken. That is right for the service and
// wrong for a gate: `check` is how a config is vetted before it is installed,
// and a typo in one awg endpoint would pass it and then run as a placeholder
// that silently drops everything routed to it.
func checkOptions(ctx context.Context, options option.Options) error {
	instance, err := box.New(box.Options{
		Context: ctx,
		Options: options,
	})
	if err != nil {
		return err
	}
	defer instance.Close()
	return invalidPlaceholders(instance)
}

func invalidPlaceholders(instance *box.Box) error {
	var invalid []error
	for _, out := range instance.Outbound().Outbounds() {
		if placeholder, isInvalid := out.(*hinvalid.Outbound); isInvalid && placeholder.InvalidOptions.Err != nil {
			invalid = append(invalid, placeholder.InvalidOptions.Err)
		}
	}
	for _, ep := range instance.Endpoint().Endpoints() {
		if placeholder, isInvalid := ep.(*hinvalid.Endpoint); isInvalid && placeholder.InvalidOptions.Err != nil {
			invalid = append(invalid, placeholder.InvalidOptions.Err)
		}
	}
	return E.Errors(invalid...)
}
