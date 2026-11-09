package cli

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	botcfg "github.com/spaiter/spaiter-vpn/internal/bot"
	"github.com/spaiter/spaiter-vpn/internal/bot/clientcfg"
	"github.com/spaiter/spaiter-vpn/internal/bot/monitor"
	"github.com/spaiter/spaiter-vpn/internal/bot/state"
	"github.com/spaiter/spaiter-vpn/internal/manage"
)

// monitorStateName is the monitor's file in the bot's data dir.
const monitorStateName = "monitor.json"

// buildMonitor assembles the health watch from the bot's config, or returns
// nil when it is switched off.
func buildMonitor(cfg botcfg.Config, api *manage.Client, store *state.Store,
	notifier monitor.Notifier, log *slog.Logger,
) *monitor.Monitor {
	mc := cfg.Monitor
	if mc.Disabled {
		return nil
	}
	loc, err := time.LoadLocation(mc.Timezone)
	if err != nil {
		loc = time.Local // Validate has already refused a bad name
	}
	from, to := mc.Quiet()

	checks := []monitor.Check{{
		Key: "core:api", Label: "API ядра", Group: monitor.GroupCore,
		Run: func(ctx context.Context) monitor.Result {
			began := time.Now()
			if err := api.Version(ctx); err != nil {
				return monitor.Result{Status: monitor.Fail, Detail: "не отвечает"}
			}
			return monitor.Result{Status: monitor.OK, Latency: time.Since(began)}
		},
	}}

	disks := mc.Disks
	if len(disks) == 0 {
		disks = []string{cfg.Paths.DataDir}
	}
	checks = append(checks, monitor.Resources{
		Limits: monitor.Limits{MemPct: mc.MemPct, DiskPct: mc.DiskPct, ConntrackPct: mc.ConntrackPct},
		Disks:  disks,
	}.Checks()...)

	world := monitor.World{}
	for _, t := range mc.World {
		checks = append(checks, monitor.Check{
			Key: "world:" + t.Name, Label: fmt.Sprintf("%s %s:%d", t.Name, t.Host, t.Port),
			Group: monitor.GroupWorld, Every: mc.WorldEvery.Build(), Threshold: 2,
			Run: func(ctx context.Context) monitor.Result { return world.Probe(ctx, t.Host, t.Port) },
		})
	}
	for _, e := range mc.Egress {
		probe := monitor.Egress{Socks: e.Socks, ExpectIP: e.ExpectIP, ProbeURL: e.ProbeURL}
		checks = append(checks, monitor.Check{
			Key: "egress:" + e.Name, Label: e.Name, Group: monitor.GroupEgress,
			Every: mc.EgressEvery.Build(),
			Run:   probe.Probe,
		})
	}

	return monitor.New(monitor.Config{
		Interval:     mc.Interval.Build(),
		Threshold:    mc.FailThreshold,
		Location:     loc,
		QuietFrom:    from,
		QuietTo:      to,
		DigestEvery:  mc.DigestEvery.Build(),
		ReportTimes:  mc.ReportTimes,
		SkipInbounds: mc.SkipInbounds,
	}, store.Path(monitorStateName), checks, coreInbounds(api), notifier, log)
}

// coreInbounds lists the core's inbounds with their ports, read from the
// running config so a /port change is followed without a restart.
func coreInbounds(api *manage.Client) monitor.InboundSource {
	return func(ctx context.Context) ([]monitor.Port, error) {
		refs, err := api.Inbounds(ctx)
		if err != nil {
			return nil, err
		}
		out := make([]monitor.Port, 0, len(refs))
		for _, ref := range refs {
			raw, err := api.Inbound(ctx, ref.Tag)
			if err != nil {
				return nil, err
			}
			in, err := clientcfg.ParseInbound(raw)
			if err != nil {
				continue
			}
			out = append(out, monitor.Port{Tag: ref.Tag, Port: in.ListenPort})
		}
		return out, nil
	}
}
