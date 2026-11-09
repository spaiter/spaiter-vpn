package profile

// Slot names one per-user credential, the unit Spec.Mint restricts and a
// credential rotation reissues.
const (
	SlotVLESSReality = "vless-reality"
	SlotVLESSWSCDN   = "vless-ws-cdn"
	SlotShadowTLS    = "shadowtls"
	SlotSnell        = "snell"
	SlotMieru        = "mieru"
	SlotHysteria2    = "hysteria2"
	// SlotTUIC covers the UUID and the password together: a TUIC account is
	// the pair, and issuing half of one would make neither half usable.
	SlotTUIC       = "tuic"
	SlotAnyTLS     = "anytls"
	SlotNaive      = "naive"
	SlotVLESSXHTTP = "vless-xhttp"
	SlotMTProto    = "mtproto"
)

// PeerSlot names a user's peer on one WireGuard endpoint.
func PeerSlot(p Protocol) string { return "peer:" + string(p) }

// CredentialSlots maps each per-user string credential to its value, empty
// when the user holds none. Listed explicitly so a new credential field has to
// be added here, and with it to every proof built on this.
func (u UserSecrets) CredentialSlots() map[string]string {
	tuic := ""
	if u.TUICUUID != "" || u.TUICPassword != "" {
		tuic = u.TUICUUID + "\x00" + u.TUICPassword
	}
	return map[string]string{
		SlotVLESSReality: u.VLESSRealityUUID,
		SlotVLESSWSCDN:   u.VLESSWSCDNUUID,
		SlotShadowTLS:    u.ShadowTLSPassword,
		SlotSnell:        u.SnellUserKey,
		SlotMieru:        u.MieruPassword,
		SlotHysteria2:    u.Hysteria2Password,
		SlotTUIC:         tuic,
		SlotAnyTLS:       u.AnyTLSPassword,
		SlotNaive:        u.NaivePassword,
		SlotVLESSXHTTP:   u.VLESSXHTTPUUID,
		SlotMTProto:      u.MTProtoSecret,
	}
}

// HeldSlots names every slot the user holds a credential or peer in.
func (u UserSecrets) HeldSlots() map[string]bool {
	held := map[string]bool{}
	for slot, value := range u.CredentialSlots() {
		if value != "" {
			held[slot] = true
		}
	}
	for protocol := range u.Peers {
		held[PeerSlot(protocol)] = true
	}
	return held
}

func (s Spec) mayMint(user, slot string) bool {
	allowed, restricted := s.Mint[user]
	return !restricted || allowed[slot]
}
