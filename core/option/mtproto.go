package option

// MTProtoInboundOptions configures a Telegram MTProto proxy inbound backed by
// github.com/9seconds/mtg. //H
type MTProtoInboundOptions struct {
	ListenOptions
	// Secret is the mtg proxy secret. Supports plain, dd- (secure) and ee-
	// (fake-TLS / domain fronting) forms, as parsed by mtglib.ParseSecret.
	// Shared by everyone who has it and attributed to nobody; kept so links
	// handed out before Users existed keep working. //H
	Secret string `json:"secret,omitempty"`
	// Users gives each person an ee- (fake-TLS) secret of their own. The
	// connection is matched to its user by the ClientHello's HMAC, and its
	// Telegram traffic is routed as that user: per-user statistics, speed
	// limits and bans apply as on every other inbound. //H
	Users []MTProtoUser `json:"users,omitempty"`
	// Concurrency caps the number of simultaneously served streams (0 = mtg default).
	Concurrency int `json:"concurrency,omitempty"`
}

// MTProtoUser is one user's fake-TLS secret. //H
type MTProtoUser struct {
	Name   string `json:"name"`
	Secret string `json:"secret"`
}
