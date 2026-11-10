package netstack

// UpdateMTU changes the MTU of the stack while it runs: new packets and new TCP connections use it.
// Hiddify's MTU discovery sets the MTU that gets through the path under the tunnel. The device's
// MTU (tun.Device.MTU), read when it starts, stays as created.
func (net *Net) UpdateMTU(mtu int) {
	net.ep.SetMTU(uint32(mtu))
}

// StackMTU is the MTU the stack uses now.
func (net *Net) StackMTU() int {
	return int(net.ep.MTU())
}
