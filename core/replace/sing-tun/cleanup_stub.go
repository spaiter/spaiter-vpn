//go:build !linux

package tun

// CleanupLeftovers: only Linux leaves routing state behind a killed TUN process.
func CleanupLeftovers(options Options, tableName string) {}
