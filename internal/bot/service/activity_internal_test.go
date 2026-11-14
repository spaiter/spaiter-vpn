package service

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/manage"
)

func conn(user, typ string, bytes int64, age time.Duration, now time.Time) manage.Connection {
	var c manage.Connection
	c.Metadata.User, c.Metadata.Type = user, typ
	c.Download = bytes
	c.Start = now.Add(-age)
	return c
}

func TestBuildActivitySeparatesUseFromProbes(t *testing.T) {
	now := time.Date(2026, 11, 14, 19, 0, 0, 0, time.UTC)
	conns := []manage.Connection{
		conn("80071", "vless/vless-reality-in", 12<<20, time.Second, now), // a stream
		conn("80071", "tuic/tuic-in", 4<<10, 2*time.Second, now),          // a probe
		conn("429366591", "awg/wg-wdtt-in", 2<<10, 5*time.Minute, now),    // an idle messenger socket
		conn("", "dns", 1<<30, time.Hour, now),                            // nobody's
	}
	rows := []manage.UserInboundStat{
		{Date: "2026-11-14", User: "80071", Inbound: "vless-reality-in", Download: 700 << 20, MaxDownload: 100 << 20, ConnCount: 967},
		{Date: "2026-11-14", User: "80071", Inbound: "anytls-in", Download: 256 << 10, MaxDownload: 5 << 10, ConnCount: 43},
		{Date: "2026-11-14", User: "141102432", Inbound: "wg-wdtt-in", Download: 800 << 10, MaxDownload: 183 << 10},
		{Date: "2026-11-13", User: "48021021", Inbound: "awg-in", Download: 1 << 30, MaxDownload: 1 << 20},
	}
	got := buildActivity(conns, rows, true, now)

	if got.Date != "2026-11-14" || !got.LiveUsers || !got.PerUserInbounds {
		t.Fatalf("header = %+v", got)
	}
	if len(got.Users) != 3 {
		t.Fatalf("users = %+v", got.Users)
	}
	vitaly := got.Users[0]
	if vitaly.User != "80071" || len(vitaly.Live) != 1 || vitaly.Live[0].Inbound != "vless-reality-in" || vitaly.LiveProbes != 1 {
		t.Errorf("busiest live user first, probes apart: %+v", vitaly)
	}
	if len(vitaly.Today) != 1 || vitaly.Today[0].Inbound != "vless-reality-in" || vitaly.TodayProbed != 1 {
		t.Errorf("probe-only inbound left out of today: %+v", vitaly.Today)
	}
	irina := got.Users[1]
	if irina.User != "429366591" || len(irina.Live) != 1 || irina.Live[0].Inbound != "wg-wdtt-in" {
		t.Errorf("a socket held open is use: %+v", irina)
	}
	owner := got.Users[2]
	if owner.User != "141102432" || len(owner.Today) != 1 || len(owner.Live) != 0 {
		t.Errorf("one large connection makes a small day count: %+v", owner)
	}
	for _, u := range got.Users {
		if u.User == "48021021" {
			t.Errorf("yesterday's row leaked into today: %+v", u)
		}
	}
}

func TestBuildActivityOnAnOldCore(t *testing.T) {
	now := time.Now()
	// A core that predates both: no user on connections, no per-user rows.
	got := buildActivity([]manage.Connection{conn("", "vless/vless-reality-in", 1<<20, time.Minute, now)}, nil, false, now)
	if got.LiveUsers || got.PerUserInbounds || len(got.Users) != 0 {
		t.Errorf("old core = %+v", got)
	}
}

func TestActivityToleratesACoreWithoutPerUserInbounds(t *testing.T) {
	s, api, _, _, _ := newService(t)
	now := time.Now()
	api.conns = []manage.Connection{conn("80071", "vless/vless-reality-in", 1<<20, time.Minute, now)}
	api.perUserErr = fmt.Errorf("GET /stats/user-inbounds: %w: 404", manage.ErrNotFound)

	got, err := s.Activity(context.Background(), now)
	if err != nil {
		t.Fatalf("a core without the route failed the view: %v", err)
	}
	if got.PerUserInbounds || !got.LiveUsers || len(got.Users) != 1 || len(got.Users[0].Live) != 1 {
		t.Errorf("activity = %+v", got)
	}

	// Any other failure is a broken API and is reported.
	api.perUserErr = errors.New("HTTP 500")
	if _, err := s.Activity(context.Background(), now); err == nil {
		t.Error("a 500 was swallowed")
	}
}
