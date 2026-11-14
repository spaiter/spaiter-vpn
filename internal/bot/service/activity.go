package service

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/spaiter/spaiter-vpn/internal/manage"
)

// What separates traffic a person rides from the probes their client sends.
//
// A client on "Auto" URL-tests every method every few minutes, so every user
// has connections on every inbound; measured on 2026-11-14 those carry 3-18 KiB
// each and never 64 KiB. A connection that downloaded more, or a day's total
// above a mebibyte, is use. A live connection held open half a minute is use
// too: a probe is answered within seconds, while a messenger's idle socket is
// exactly the traffic that shows which method someone is on.
const (
	streamBytes     = 64 << 10
	usedDailyBytes  = 1 << 20
	heldOpenSeconds = 30
)

// InboundUse is one user's traffic on one inbound.
type InboundUse struct {
	Inbound string
	Bytes   int64 // upload + download
	Conns   int64
}

// UserActivity is which inbounds one user is on.
type UserActivity struct {
	User string
	// Live are the inbounds carrying this user's open connections that look
	// like use, busiest first.
	Live []InboundUse
	// LiveProbes counts open connections that look like probes only.
	LiveProbes int
	// Today are the inbounds this user's closed connections used today,
	// busiest first, probe-only inbounds left out.
	Today []InboundUse
	// TodayProbed counts inbounds that saw only probes today.
	TodayProbed int
}

// LiveBytes is the traffic of the user's open connections that look like use.
func (a UserActivity) LiveBytes() int64 { return sumBytes(a.Live) }

// TodayBytes is the traffic of the user's closed connections today.
func (a UserActivity) TodayBytes() int64 { return sumBytes(a.Today) }

func sumBytes(list []InboundUse) (total int64) {
	for _, use := range list {
		total += use.Bytes
	}
	return total
}

// Activity is the admin's view of who is on which method.
type Activity struct {
	// Date is the day Today covers, as the core dates it (UTC); empty when
	// nothing has been counted yet.
	Date  string
	Users []UserActivity
	// LiveUsers is false on a core that does not say whose a connection is,
	// and PerUserInbounds false on one without per-user inbound accounting.
	// Either way the view is partial, and saying so beats an empty list.
	LiveUsers       bool
	PerUserInbounds bool
}

// Activity collects who is on which method: right now from the open
// connections, and today from the core's per-user, per-inbound accounting.
func (s *Service) Activity(ctx context.Context, now time.Time) (Activity, error) {
	conns, err := s.api.Connections(ctx)
	if err != nil {
		return Activity{}, fmt.Errorf("service: connections: %w", err)
	}
	rows, err := s.api.UserInboundStats(ctx, 1)
	perUser := true
	if errors.Is(err, manage.ErrNotFound) {
		perUser, err = false, nil
	}
	if err != nil {
		return Activity{}, fmt.Errorf("service: user inbound stats: %w", err)
	}
	return buildActivity(conns, rows, perUser, now), nil
}

func buildActivity(conns []manage.Connection, rows []manage.UserInboundStat, perUser bool, now time.Time) Activity {
	out := Activity{PerUserInbounds: perUser}
	users := map[string]*UserActivity{}
	get := func(name string) *UserActivity {
		if a := users[name]; a != nil {
			return a
		}
		a := &UserActivity{User: name}
		users[name] = a
		return a
	}

	live := map[string]map[string]*InboundUse{}
	for _, conn := range conns {
		name := conn.Metadata.User
		if name == "" {
			continue
		}
		out.LiveUsers = true
		bytes := conn.Upload + conn.Download
		held := !conn.Start.IsZero() && now.Sub(conn.Start) >= heldOpenSeconds*time.Second
		if bytes < streamBytes && !held {
			get(name).LiveProbes++
			continue
		}
		get(name)
		if live[name] == nil {
			live[name] = map[string]*InboundUse{}
		}
		use := live[name][conn.Inbound()]
		if use == nil {
			use = &InboundUse{Inbound: conn.Inbound()}
			live[name][conn.Inbound()] = use
		}
		use.Bytes += bytes
		use.Conns++
	}
	for name, byInbound := range live {
		for _, use := range byInbound {
			users[name].Live = append(users[name].Live, *use)
		}
		sortUses(users[name].Live)
	}

	// Rows come newest day first; only the newest day is "today".
	for _, row := range rows {
		if out.Date == "" {
			out.Date = row.Date
		}
		if row.Date != out.Date || row.User == "" {
			continue
		}
		a := get(row.User)
		bytes := row.Upload + row.Download
		if bytes < usedDailyBytes && row.MaxDownload < streamBytes {
			a.TodayProbed++
			continue
		}
		a.Today = append(a.Today, InboundUse{Inbound: row.Inbound, Bytes: bytes, Conns: row.ConnCount})
	}

	for _, a := range users {
		sortUses(a.Today)
		out.Users = append(out.Users, *a)
	}
	// Who is on something now first, then by today's traffic.
	sort.Slice(out.Users, func(i, j int) bool {
		a, b := out.Users[i], out.Users[j]
		if a.LiveBytes() != b.LiveBytes() {
			return a.LiveBytes() > b.LiveBytes()
		}
		if a.TodayBytes() != b.TodayBytes() {
			return a.TodayBytes() > b.TodayBytes()
		}
		return a.User < b.User
	})
	return out
}

func sortUses(list []InboundUse) {
	sort.Slice(list, func(i, j int) bool {
		if list[i].Bytes != list[j].Bytes {
			return list[i].Bytes > list[j].Bytes
		}
		return list[i].Inbound < list[j].Inbound
	})
}
