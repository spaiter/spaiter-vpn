package manage

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Connection is one live connection from GET /connections, reduced to what a
// per-user view needs.
type Connection struct {
	ID       string    `json:"id"`
	Upload   int64     `json:"upload"`
	Download int64     `json:"download"`
	Start    time.Time `json:"start"`
	Metadata struct {
		Network         string `json:"network"`
		Type            string `json:"type"` // "<inbound type>/<inbound tag>"
		SourceIP        string `json:"sourceIP"`
		DestinationIP   string `json:"destinationIP"`
		DestinationPort string `json:"destinationPort"`
		Host            string `json:"host"`
		// User is empty on a core that predates it, and on connections no
		// inbound user owns (DNS, the core's own probes).
		User string `json:"user"`
	} `json:"metadata"`
}

// Inbound is the inbound tag of a connection, without its type prefix.
func (c Connection) Inbound() string {
	if _, tag, ok := strings.Cut(c.Metadata.Type, "/"); ok {
		return tag
	}
	return c.Metadata.Type
}

// Connections lists the connections open right now.
func (c *Client) Connections(ctx context.Context) ([]Connection, error) {
	raw, err := c.do(ctx, http.MethodGet, "/connections", nil)
	if err != nil {
		return nil, err
	}
	var snapshot struct {
		Connections []Connection `json:"connections"`
	}
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return nil, fmt.Errorf("decode connections %q: %w", truncate(raw), err)
	}
	return snapshot.Connections, nil
}

// UserInboundStat is one row of GET /stats/user-inbounds: one user's closed
// connections on one inbound on one day.
type UserInboundStat struct {
	Date        string `json:"date"`
	User        string `json:"user"`
	Inbound     string `json:"inbound"`
	Upload      int64  `json:"upload"`
	Download    int64  `json:"download"`
	ConnCount   int64  `json:"conn_count"`
	BulkConns   int64  `json:"bulk_conns"`
	MaxDownload int64  `json:"max_download"`
}

// UserInboundStats is the per-user, per-inbound accounting of the last days.
// A core that predates the route answers ErrNotFound.
func (c *Client) UserInboundStats(ctx context.Context, days int) ([]UserInboundStat, error) {
	raw, err := c.do(ctx, http.MethodGet, "/stats/user-inbounds?days="+strconv.Itoa(days), nil)
	if err != nil {
		return nil, err
	}
	var list []UserInboundStat
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("decode user inbound stats %q: %w", truncate(raw), err)
	}
	return list, nil
}
